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
    {"action":"drive","dir":"left"}      -> TL  (разворот на месте влево)
    {"action":"drive","dir":"right"}     -> TR
    {"action":"drive","dir":"stop"}      -> MS
    {"action":"tank","left":200,"right":-200}  -> TANK 200 -200  (или ключи l/r)
    {"action":"turret","dir":"left","step":1} -> PANL 1  (мелкий шаг — плавнее при удержании)
    {"action":"pan","deg":45}            -> PAN 45
    {"action":"tilt","deg":20}           -> TILT 20
    {"action":"aim","pan":45,"tilt":20}  -> TURRET 45 20
    {"action":"turret_smooth","dir":"left","v":18} -> PL 18  (или без v — скорость по умолчанию в прошивке)
    {"action":"turret_smooth","dir":"right"}       -> PR
    {"action":"turret_stop"}             -> TS  (стоп плавного хода; то же, что TSTOP)
    … pan_vel / tilt_vel / turret_vel -> PANV / TILTV / TURRETV …
    {"action":"home"}                    -> HOME

Рекомендация для стрелок: **turret_smooth** + **turret_stop**; дополнительно PANV/TILTV и пошаговый **turret** / ``--romeo-turret-step``.

Ответ на каждую входную строку (одна строка JSON)::

    {"ok":true,"reply":"OK\\r\\n"}
    {"ok":false,"error":"..."}
"""

from __future__ import annotations

import errno
import json
import logging
import socket
import threading
from rpi_tools.errors import TcpBindError
from rpi_tools.romeo_usb import romeo_exchange

log = logging.getLogger("camstream")


def _clamp_speed(v: int) -> int:
    return max(-255, min(255, int(v)))


def _drive_commands(direction: str, _tank_speed: int) -> list[str]:
    """Соответствие прошивке: влево/вправо — TL/TR (не M1/M2)."""
    d = direction.strip().lower()
    if d == "forward":
        return ["MF"]
    if d == "back":
        return ["MB"]
    if d == "stop":
        return ["MS"]
    if d == "left":
        return ["TL"]
    if d == "right":
        return ["TR"]
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
    return f"{cmd} {_fmt_deg(step)}"


def _turret_vel_lines(obj: dict) -> list[str]:
    pv = obj.get("pan")
    tv = obj.get("tilt")
    if pv is not None and tv is not None:
        return [f"TURRETV {_fmt_deg(pv)} {_fmt_deg(tv)}"]
    if pv is not None:
        return [f"PANV {_fmt_deg(pv)}"]
    if tv is not None:
        return [f"TILTV {_fmt_deg(tv)}"]
    raise ValueError('turret_vel: укажите «pan» и/или «tilt» (град/с)')


def _single_axis_vel(act_name: str, obj: dict, prefix: str) -> list[str]:
    v = obj.get("v")
    if v is None:
        raise ValueError(f'{act_name}: нужно поле «v» (град/с, знак — направление)')
    return [f"{prefix} {_fmt_deg(v)}"]


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
    return f"{cmd} {_fmt_deg(v)}"


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
    raise ValueError(
        "неизвестный JSON: поле «romeo» или action: drive|tank|turret|turret_smooth|"
        "pan|tilt|aim|pan_vel|tilt_vel|turret_vel|turret_stop|home"
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
    return True, "".join(parts), ""


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
    buf = bytearray()
    lead_delay = float(open_delay)
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
                )
                lead_delay = 0.0
                if ok:
                    rsp = {"ok": True, "reply": reply}
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
    read_timeout: float = 1.0,
    read_idle: float = 0.2,
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
        "romeo-control: слушаем TCP 0.0.0.0:%s → USB %s @ %s (drive вбок: TL/TR; TANK — см. JSON action=tank)",
        bind_port,
        romeo_port,
        baud,
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
