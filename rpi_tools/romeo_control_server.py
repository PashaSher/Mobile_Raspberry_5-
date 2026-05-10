"""
TCP-сервер на Raspberry Pi: приём команд по Wi‑Fi/LAN и пересылка строк на Romeo (USB CDC).

Строки на USB совпадают с текстовым протоколом прошивки::

    MF MB MS/STOP | TL TR | TANK l r | M1 n M2 n |
    PAN TILT TURRET | PANL PANR TILTU TILTD |
    PL PR TU TD [v] | TS TSTOP | PANV TILTV TURRETV | HOME POS |
    S1 n S2 n | FIRE/IR PING ?

Протокол «ПК → Pi» (UTF-8, строки через \\n), ответы — NDJSON в ту же сессию.

1) Прямой текст — те же команды, что в Serial (одна строка = одна команда).

2) JSON (удобно для кнопок/стрелок на удалённом клиенте)::

    {"romeo":"MF"}                       — произвольная одна строка
    {"action":"drive","dir":"forward"}   -> MF
    {"action":"drive","dir":"back"}      -> MB
    {"action":"drive","dir":"left"}      -> TANK -mag mag (разворот; mag ≈ tank_speed×scale, см. config)
    {"action":"drive","dir":"right"}     -> TANK mag -mag
    {"action":"drive","dir":"stop"}      -> MS
    {"action":"tank","left":200,"right":-200}  -> TANK 200 -200  (или ключи l/r)
    {"action":"turret","dir":"left","step":1} -> PANL 1  (мелкий шаг — плавнее при удержании)
    {"action":"pan","deg":45}            -> PAN 45
    {"action":"tilt","deg":20}           -> TILT 20
    {"action":"aim","pan":45,"tilt":20}  -> TURRET 45 20
    {"action":"turret_smooth","dir":"left","v":18} -> PL с v×scale (или без v — скорость по умолчанию в прошивке)
    {"action":"turret_smooth","dir":"right"}       -> PR
    {"action":"turret_stop"}             -> TS  (стоп плавного хода; то же, что TSTOP)
    … pan_vel / tilt_vel / turret_vel -> PANV / TILTV / TURRETV …
    {"action":"home"}                    -> HOME
    {"action":"adc_read"}                -> A1 по умолчанию (канал из ROMEO_ADC_DEFAULT_CHANNEL на Pi / в config)
    {"action":"adc_read","ch":3}         -> A3
    {"action":"adc_vcc"}               -> VCC  (калибровка AVCC по bandgap)
    {"action":"adc_vref"}              -> VREF (текущая опора для raw→mВ)
    {"action":"adc_vref_set","mv":4980}-> VREF 4980
    {"action":"adc_vref_auto"}         -> VREF AUTO (= как VCC)
    {"action":"vbat_read"}             -> VBAT  (батарея по прошивке: делитель на A1)

Рекомендация для стрелок: **turret_smooth** + **turret_stop**; дополнительно PANV/TILTV и пошаговый **turret** / ``--romeo-turret-step``.

Повтор **той же строки** команды, что уже была отправлена на USB по этому TCP‑соединению, **не дублируется**, пока не придёт другая команда (или команда вне фильтра — тогда считается смена контекста). Исключения: абсолютные углы (**PAN**/**TILT**/**TURRET** с числом), шаг башни (**PANL**/**PANR**/**TILTU**/**TILTD** с аргументом), чувствительные префиксы (**HOME**, **M1**/**M2**, **FIRE**, …). Ответ JSON по-прежнему ``{"ok":true}``, поле ``reply`` может быть пустым.

Ответ на каждую входную строку (одна строка JSON)::

    {"ok":true,"reply":"OK\\r\\n"}
    {"ok":false,"error":"..."}

Для ответа АЦП (после команды ``A0`` … ``A5`` или JSON ``adc_read``) к успешному объекту добавляются поля
``adc_ch``, ``adc_raw``, ``adc_pin_mv``, ``adc_pin_mv_cal``, ``battery_v`` (см. ``rpi_tools/config.py``: делитель и опционально ``ROMEO_ADC_FIRMWARE_MV_SCALE``).
После ``VBAT`` / JSON ``vbat_read``: ``vbat_*`` и ``battery_v`` после ``battery_display_volts_to_multimeter`` (по умолчанию две точки ``ROMEO_BATTERY_CAL_*``, см. ``rpi_tools/config.py``).
Ответы ``VCC …``, ``VREF …`` добавляют поля ``vcc_mv`` / ``vref_mv`` (целые мВ).

Поле **`reply`** — сырой ответ прошивки Romeo (может быть пустым).
"""

from __future__ import annotations

import errno
import json
import logging
import socket
import threading
from rpi_tools.errors import TcpBindError
from rpi_tools.config import (
    ROMEO_ADC_DEFAULT_CHANNEL,
    ROMEO_PIVOT_TANK_SCALE,
    ROMEO_TURRET_STEP_SCALE,
    ROMEO_TURRET_VEL_SCALE,
    adc_pin_mv_calibrated,
    battery_display_volts_to_multimeter,
    battery_volts_from_adc_pin_mv,
)
from rpi_tools.romeo_usb import ROMEO_ADC_CHANNEL_COUNT, parse_adc_reply, parse_vbat_reply, romeo_exchange

log = logging.getLogger("camstream")

# Повтор той же строки (см. _ctrl_spam_dedup_key), что уже ушла на USB, не отправляется снова, пока не сменится команда.

# Не сливать: абсолютные углы и пошаговая башня с явным аргументом (каждый шаг — отдельное движение).
_ROMEO_SPAM_NEVER_STEP = frozenset({"PANL", "PANR", "TILTU", "TILTD"})
_ROMEO_SPAM_NEVER_ABSOLUTE = frozenset({"PAN", "TILT", "TURRET"})
# Одно слово или любая длина — не сливаем (редкие / чувствительные к пропускам).
_ROMEO_SPAM_NEVER_HEAD = frozenset(
    {
        "HOME",
        "POS",
        "S1",
        "S2",
        "M1",
        "M2",
        "FIRE",
        "IR",
        "PING",
        "LTG",
        "A0",
        "A1",
        "A2",
        "A3",
        "A4",
        "A5",
        "VCC",
        "VREF",
        "VBAT",
    }
)


def _ctrl_spam_dedup_key(cmd_norm: str) -> str | None:
    """Если не None — повтор того же ключа подряд не шлём на USB (только при смене команды)."""
    if not cmd_norm:
        return None
    parts = cmd_norm.split()
    if not parts:
        return None
    head = parts[0].upper()
    canonical = " ".join([head] + parts[1:])

    if head in _ROMEO_SPAM_NEVER_HEAD:
        return None
    if head in _ROMEO_SPAM_NEVER_ABSOLUTE and len(parts) >= 2:
        return None
    if head in _ROMEO_SPAM_NEVER_STEP and len(parts) >= 2:
        return None

    return canonical


def _clamp_speed(v: int) -> int:
    return max(-255, min(255, int(v)))


def _drive_commands(direction: str, tank_speed: int) -> list[str]:
    """Вбок: дифференциал TANK (mag из tank_speed×ROMEO_PIVOT_TANK_SCALE), мягче фиксированных TL/TR."""
    d = direction.strip().lower()
    base = abs(int(tank_speed))
    mag = max(1, int(round(base * ROMEO_PIVOT_TANK_SCALE)))
    if d == "forward":
        return ["MF"]
    if d == "back":
        return ["MB"]
    if d == "stop":
        return ["MS"]
    if d == "left":
        return [f"TANK {_clamp_speed(-mag)} {_clamp_speed(mag)}"]
    if d == "right":
        return [f"TANK {_clamp_speed(mag)} {_clamp_speed(-mag)}"]
    raise ValueError(f"неизвестный drive.dir: {direction!r}")


def _tank_line(obj: dict) -> str:
    lv = obj.get("left", obj.get("l"))
    rv = obj.get("right", obj.get("r"))
    if lv is None or rv is None:
        raise ValueError('ожидались поля "left"/"right" (или l/r) для TANK l r')
    return f"TANK {_clamp_speed(lv)} {_clamp_speed(rv)}"


def _fmt_deg(v: object) -> str:
    """Число для строк прошивки PAN/TILT/TANK/PANL 2."""
    try:
        x = float(v)
    except (TypeError, ValueError) as e:
        raise ValueError("ожидалось число") from e
    if abs(x - round(x)) < 1e-6:
        return str(int(round(x)))
    return repr(x)


def _turret_line(obj: dict, default_step: int | float | None) -> str:
    """PANL [s], TILTU [s] … — опциональный шаг для плавности."""
    d = str(obj.get("dir", "")).strip().lower()
    m = {
        "up": "TILTU",
        "down": "TILTD",
        "left": "PANL",
        "right": "PANR",
    }
    if d not in m:
        raise ValueError(f"неизвестный turret.dir: {obj.get('dir')!r}")
    cmd = m[d]
    step = obj.get("step")
    if step is None:
        step = default_step
    if step is None:
        return cmd
    scaled = float(step) * ROMEO_TURRET_STEP_SCALE
    return f"{cmd} {_fmt_deg(scaled)}"


def _turret_vel_lines(obj: dict) -> list[str]:
    pv = obj.get("pan")
    tv = obj.get("tilt")
    if pv is not None and tv is not None:
        return [
            f"TURRETV {_fmt_deg(float(pv) * ROMEO_TURRET_VEL_SCALE)} {_fmt_deg(float(tv) * ROMEO_TURRET_VEL_SCALE)}"
        ]
    if pv is not None:
        return [f"PANV {_fmt_deg(float(pv) * ROMEO_TURRET_VEL_SCALE)}"]
    if tv is not None:
        return [f"TILTV {_fmt_deg(float(tv) * ROMEO_TURRET_VEL_SCALE)}"]
    raise ValueError('turret_vel: укажите «pan» и/или «tilt» (град/с)')


def _single_axis_vel(act_name: str, obj: dict, prefix: str) -> list[str]:
    v = obj.get("v")
    if v is None:
        raise ValueError(f'{act_name}: нужно поле «v» (град/с, знак — направление)')
    scaled = float(v) * ROMEO_TURRET_VEL_SCALE
    return [f"{prefix} {_fmt_deg(scaled)}"]


def _turret_smooth_line(obj: dict) -> str:
    """PL/PR/TU/TD [v] — плавный ход по направлению; v опционален (kTurretDefaultRate)."""
    d = str(obj.get("dir", "")).strip().lower()
    m = {"left": "PL", "right": "PR", "up": "TU", "down": "TD"}
    if d not in m:
        raise ValueError(f"turret_smooth.dir: ожидалось left|right|up|down, получено {obj.get('dir')!r}")
    cmd = m[d]
    v = obj.get("v", obj.get("rate"))
    if v is None:
        return cmd
    scaled = float(v) * ROMEO_TURRET_VEL_SCALE
    return f"{cmd} {_fmt_deg(scaled)}"


def _json_to_romeo_lines(
    obj: dict,
    tank_speed: int,
    turret_step_default: int | float | None,
) -> list[str]:
    if not isinstance(obj, dict):
        raise ValueError("ожидался JSON-объект")
    if "romeo" in obj:
        line = obj["romeo"]
        if not isinstance(line, str) or not line.strip():
            raise ValueError("поле «romeo» должно быть непустой строкой")
        return [line.strip()]
    act = obj.get("action")
    if act == "drive":
        return _drive_commands(str(obj.get("dir", "")), tank_speed)
    if act == "tank":
        return [_tank_line(obj)]
    if act == "turret":
        return [_turret_line(obj, turret_step_default)]
    if act == "turret_smooth":
        return [_turret_smooth_line(obj)]
    if act == "pan":
        deg = obj.get("deg")
        if deg is None:
            raise ValueError('pan: нужно поле «deg»')
        return [f"PAN {_fmt_deg(deg)}"]
    if act == "tilt":
        deg = obj.get("deg")
        if deg is None:
            raise ValueError('tilt: нужно поле «deg»')
        return [f"TILT {_fmt_deg(deg)}"]
    if act == "aim":
        pv = obj.get("pan")
        tv = obj.get("tilt")
        if pv is None or tv is None:
            raise ValueError('aim: нужны поля «pan» и «tilt»')
        return [f"TURRET {_fmt_deg(pv)} {_fmt_deg(tv)}"]
    if act == "pan_vel":
        return _single_axis_vel("pan_vel", obj, "PANV")
    if act == "tilt_vel":
        return _single_axis_vel("tilt_vel", obj, "TILTV")
    if act == "turret_vel":
        return _turret_vel_lines(obj)
    if act == "turret_stop":
        return ["TS"]
    if act == "home":
        return ["HOME"]
    if act in ("adc_read", "adc"):
        ch = obj.get("ch", obj.get("channel", ROMEO_ADC_DEFAULT_CHANNEL))
        try:
            n = int(ch)
        except (TypeError, ValueError) as e:
            raise ValueError("adc_read: поле «ch» должно быть целым 0..5") from e
        if not (0 <= n < ROMEO_ADC_CHANNEL_COUNT):
            raise ValueError(f"adc_read: ch вне 0..{ROMEO_ADC_CHANNEL_COUNT - 1}")
        return [f"A{n}"]
    if act in ("adc_vcc", "vcc"):
        return ["VCC"]
    if act in ("adc_vref_set", "vref_set"):
        mv = obj.get("mv")
        if mv is None:
            raise ValueError("adc_vref_set: нужно целое поле «mv» (500..7000)")
        try:
            n = int(mv)
        except (TypeError, ValueError) as e:
            raise ValueError("adc_vref_set: «mv» должно быть целым числом") from e
        if not (500 <= n <= 7000):
            raise ValueError("adc_vref_set: mv вне диапазона 500..7000")
        return [f"VREF {n}"]
    if act in ("adc_vref_auto", "vref_auto"):
        return ["VREF AUTO"]
    if act in ("adc_vref", "vref"):
        return ["VREF"]
    if act in ("vbat_read", "vbat"):
        return ["VBAT"]
    raise ValueError(
        "неизвестный JSON: поле «romeo» или action: drive|tank|turret|turret_smooth|"
        "pan|tilt|aim|pan_vel|tilt_vel|turret_vel|turret_stop|home|adc_read|"
        "adc_vcc|adc_vref|adc_vref_set|adc_vref_auto|vbat_read"
    )


def _process_line(
    line: str,
    *,
    romeo_port: str,
    baud: int,
    lead_open_delay: float,
    tank_speed: int,
    turret_step_default: int | float | None,
    read_timeout: float,
    read_idle: float,
    drive_spam_state: dict | None = None,
) -> tuple[bool, str, str]:
    """
    Возвращает (ok, reply_text, error_message).
    reply_text — сырой ответ Romeo (может быть пустым).
    """
    raw = line.strip()
    if not raw:
        return True, "", ""

    cmds: list[str]
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            return False, "", f"JSON: {e}"
        try:
            cmds = _json_to_romeo_lines(obj, tank_speed, turret_step_default)
        except ValueError as e:
            return False, "", str(e)
    else:
        cmds = [raw]

    parts: list[str] = []
    for idx, cmd in enumerate(cmds):
        cmd_norm = cmd.strip()
        spam_key = _ctrl_spam_dedup_key(cmd_norm)
        if drive_spam_state is not None and spam_key is not None:
            prev = drive_spam_state.get("last_spam")
            if prev == spam_key:
                log.debug("romeo-control: без изменений %s — не отправляем на USB", spam_key)
                continue
        try:
            chunk = romeo_exchange(
                romeo_port,
                baud,
                cmd,
                append_lf=True,
                read_timeout=read_timeout,
                read_idle=read_idle,
                open_delay=lead_open_delay if idx == 0 else 0.0,
                log_send=False,
            )
        except (OSError, RuntimeError) as e:
            return False, "", str(e)
        if chunk:
            parts.append(chunk.decode("utf-8", errors="replace"))
        if drive_spam_state is not None:
            if spam_key is not None:
                drive_spam_state["last_spam"] = spam_key
            else:
                drive_spam_state["last_spam"] = None
    return True, "".join(parts), ""


def _control_ok_payload(reply: str) -> dict:
    """NDJSON для успешного ответа; строки АЦП / VBAT / VCC / VREF обогащают поля."""
    payload: dict = {"ok": True, "reply": reply}
    text_norm = reply.replace("\r\n", "\n")
    for raw_line in text_norm.splitlines():
        parts = raw_line.strip().split()
        if len(parts) >= 2:
            head = parts[0].upper()
            if head == "VCC":
                try:
                    payload["vcc_mv"] = int(parts[1])
                except ValueError:
                    pass
            elif head == "VREF":
                try:
                    payload["vref_mv"] = int(parts[1])
                except ValueError:
                    pass
    data = reply.encode("utf-8", errors="replace")
    got_vbat = False
    try:
        bat_mv, vbat_raw, vbat_pin_mv = parse_vbat_reply(data)
        payload["vbat_battery_mv"] = bat_mv
        payload["vbat_raw"] = vbat_raw
        payload["vbat_pin_mv"] = vbat_pin_mv
        payload["battery_v"] = round(battery_display_volts_to_multimeter(bat_mv / 1000.0), 2)
        got_vbat = True
    except ValueError:
        pass
    try:
        ch, raw, pin_mv = parse_adc_reply(data)
    except ValueError:
        return payload
    payload["adc_ch"] = ch
    payload["adc_raw"] = raw
    payload["adc_pin_mv"] = pin_mv
    cal_mv = adc_pin_mv_calibrated(pin_mv)
    payload["adc_pin_mv_cal"] = round(cal_mv)
    if not got_vbat:
        payload["battery_v"] = round(battery_volts_from_adc_pin_mv(pin_mv), 2)
    return payload


def _client_loop(
    conn: socket.socket,
    addr: tuple,
    *,
    romeo_port: str,
    baud: int,
    open_delay: float,
    tank_speed: int,
    turret_step_default: int | float | None,
    read_timeout: float,
    read_idle: float,
) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    buf = bytearray()
    lead_delay = float(open_delay)
    drive_spam_state: dict = {}
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf.extend(data)
            while True:
                i = buf.find(b"\n")
                if i < 0:
                    break
                line = bytes(buf[:i]).decode("utf-8", errors="replace")
                del buf[: i + 1]
                ok, reply, err = _process_line(
                    line,
                    romeo_port=romeo_port,
                    baud=baud,
                    lead_open_delay=lead_delay,
                    tank_speed=tank_speed,
                    turret_step_default=turret_step_default,
                    read_timeout=read_timeout,
                    read_idle=read_idle,
                    drive_spam_state=drive_spam_state,
                )
                lead_delay = 0.0
                if ok:
                    rsp = _control_ok_payload(reply)
                else:
                    rsp = {"ok": False, "error": err}
                conn.sendall((json.dumps(rsp, ensure_ascii=False) + "\n").encode("utf-8"))
    except OSError as e:
        if getattr(e, "errno", None) not in (errno.EPIPE, errno.ECONNRESET):
            log.debug("romeo-control: клиент %s: %s", addr, e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_romeo_control_server(
    bind_port: int,
    *,
    romeo_port: str,
    baud: int = 115200,
    open_delay: float = 0.0,
    tank_speed: int = 200,
    turret_step_default: int | float | None = None,
    read_timeout: float = 0.45,
    read_idle: float = 0.03,
) -> tuple[socket.socket, threading.Thread]:
    """
    Слушает TCP ``0.0.0.0:bind_port``; каждое соединение — независимые строки команд.
    Возвращает сокет сервера и поток accept-loop (daemon).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", bind_port))
        srv.listen(8)
    except OSError as e:
        log.error("romeo-control: не удалось bind 0.0.0.0:%s: %s", bind_port, e)
        en = getattr(e, "errno", None)
        if en == errno.EADDRINUSE or "Address already in use" in str(e):
            log.error(
                "Порт %s занят — часто второй экземпляр camstream/stream_camera или systemd. "
                "Проверка: ss -tlnp '( sport = :%s )'; временно без сервера: --romeo-control-port 0",
                bind_port,
                bind_port,
            )
        try:
            srv.close()
        except OSError:
            pass
        raise TcpBindError("romeo-control") from e
    if turret_step_default is not None:
        log.info(
            "romeo-control: по умолчанию шаг башни для action=turret без «step»: %s° (PANL/TILTU …)",
            turret_step_default,
        )
    log.info(
        "romeo-control: слушаем TCP 0.0.0.0:%s → USB %s @ %s (вбок JSON drive: TANK из --romeo-tank-speed×%.2g; явный TANK — без изменения)",
        bind_port,
        romeo_port,
        baud,
        ROMEO_PIVOT_TANK_SCALE,
    )

    def accept_loop() -> None:
        while True:
            try:
                c, a = srv.accept()
            except OSError:
                break
            th = threading.Thread(
                target=_client_loop,
                args=(c, a),
                kwargs={
                    "romeo_port": romeo_port,
                    "baud": baud,
                    "open_delay": open_delay,
                    "tank_speed": tank_speed,
                    "turret_step_default": turret_step_default,
                    "read_timeout": read_timeout,
                    "read_idle": read_idle,
                },
                daemon=True,
            )
            th.start()

    th_main = threading.Thread(target=accept_loop, daemon=True)
    th_main.start()
    return srv, th_main
