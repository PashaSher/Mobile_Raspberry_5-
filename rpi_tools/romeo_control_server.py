"""
TCP-сервер на Raspberry Pi: приём команд по Wi‑Fi/LAN и пересылка строк на Romeo (USB CDC).

Строки на USB совпадают с текстовым протоколом прошивки::

    MF MB MS/STOP | TL TR | TANK l r | M1 n M2 n |
    PAN TILT TURRET | PANL PANR TILTU TILTD | HOME POS |
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
    {"action":"turret","dir":"up"}       -> TILTU … и т.д.
    {"action":"home"}                    -> HOME

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


def _turret_command(direction: str) -> str:
    d = direction.strip().lower()
    m = {
        "up": "TILTU",
        "down": "TILTD",
        "left": "PANL",
        "right": "PANR",
    }
    if d not in m:
        raise ValueError(f"неизвестный turret.dir: {direction!r}")
    return m[d]


def _json_to_romeo_lines(obj: dict, tank_speed: int) -> list[str]:
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
        return [_turret_command(str(obj.get("dir", "")))]
    if act == "home":
        return ["HOME"]
    raise ValueError("неизвестный JSON: ожидались action/drive|tank|turret|home или поле romeo")


def _process_line(
    line: str,
    *,
    romeo_port: str,
    baud: int,
    lead_open_delay: float,
    tank_speed: int,
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
            cmds = _json_to_romeo_lines(obj, tank_speed)
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
    read_timeout: float = 1.0,
    read_idle: float = 0.2,
) -> tuple[socket.socket, threading.Thread]:
    """
    Слушает TCP ``0.0.0.0:bind_port``; каждое соединение — независимые строки команд.
    Возвращает сокет сервера и поток accept-loop (daemon).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", bind_port))
    srv.listen(8)
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
                    "read_timeout": read_timeout,
                    "read_idle": read_idle,
                },
                daemon=True,
            )
            th.start()

    th_main = threading.Thread(target=accept_loop, daemon=True)
    th_main.start()
    return srv, th_main
