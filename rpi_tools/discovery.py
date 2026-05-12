"""UDP discovery (handshake в LAN между Pi и приложением на ПК)."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time

from rpi_tools.config import DISCOVERY_REQ, DISCOVERY_RSP, DISCOVERY_VERSION

log = logging.getLogger("camstream")


def _discovery_request_payload(token: str) -> bytes:
    return (
        json.dumps(
            {
                "v": DISCOVERY_VERSION,
                "cmd": DISCOVERY_REQ,
                "token": token,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _parse_discovery_response(data: bytes) -> dict | None:
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if msg.get("v") != DISCOVERY_VERSION or msg.get("cmd") != DISCOVERY_RSP:
        return None
    if "tcp" not in msg:
        return None
    return msg


def discover_receivers(
    discover_port: int,
    token: str,
    timeout: float,
    wait_after_send: float = 0.15,
) -> list[tuple[str, int, int | None, str | None, int | None]]:
    """
    Шлёт UDP broadcast и собирает ответы на handshake (discover).
    Возвращает список (ip, tcp_port, http_port|None, name, control_tcp|None).
    """
    log.info("discovery: широковещательный запрос UDP → порт %s, таймаут %.1f с", discover_port, timeout)
    req = _discovery_request_payload(token)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.4)

    for dest in ("255.255.255.255", "<broadcast>"):
        try:
            sock.sendto(req, (dest, discover_port))
        except OSError:
            pass
    time.sleep(wait_after_send)

    deadline = time.monotonic() + timeout
    seen: set[tuple[str, int, int | None, int | None]] = set()
    out: list[tuple[str, int, int | None, str | None, int | None]] = []

    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(0.5, remaining))
        try:
            data, addr = sock.recvfrom(4096)
        except TimeoutError:
            continue
        msg = _parse_discovery_response(data)
        if msg is None:
            continue
        ip = addr[0]
        tcp_p = int(msg["tcp"])
        http_p = msg.get("http")
        if http_p is not None:
            http_p = int(http_p)
        ctl_p = msg.get("control")
        if ctl_p is not None:
            ctl_p = int(ctl_p)
        name = msg.get("name")
        key = (ip, tcp_p, http_p, ctl_p)
        if key in seen:
            continue
        seen.add(key)
        out.append((ip, tcp_p, http_p, name if isinstance(name, str) else None, ctl_p))
        log.info(
            "discovery: ответ от %s tcp=%s http=%s control=%s name=%s",
            ip,
            tcp_p,
            http_p,
            ctl_p if ctl_p is not None else "—",
            name or "—",
        )

    sock.close()
    log.info("discovery: итого уникальных ответов: %d", len(out))
    return out


def _discovery_responder_loop(
    udp_sock: socket.socket,
    tcp_port: int,
    http_port: int | None,
    control_tcp_port: int | None,
    token: str | None,
    video_transport: str | None,
    video_codec: str | None,
    video_mode: str | None,
) -> None:
    while True:
        try:
            data, addr = udp_sock.recvfrom(4096)
        except OSError:
            break
        try:
            msg = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if msg.get("v") != DISCOVERY_VERSION or msg.get("cmd") != DISCOVERY_REQ:
            continue
        req_tok = msg.get("token") or ""
        if token and req_tok != token:
            continue
        rsp: dict = {
            "v": DISCOVERY_VERSION,
            "cmd": DISCOVERY_RSP,
            "tcp": tcp_port,
            "name": socket.gethostname(),
        }
        if http_port is not None:
            rsp["http"] = http_port
        if control_tcp_port is not None and control_tcp_port > 0:
            rsp["control"] = control_tcp_port
        if video_transport:
            rsp["video_transport"] = video_transport
        if video_codec:
            rsp["video_codec"] = video_codec
        if video_mode:
            rsp["video_mode"] = video_mode
        try:
            udp_sock.sendto(json.dumps(rsp, separators=(",", ":")).encode("utf-8"), addr)
            log.debug("discovery: отправлен hello → %s tcp=%s", addr[0], tcp_port)
        except OSError:
            pass


def _start_discovery_responder(
    discover_port: int,
    tcp_port: int,
    http_port: int | None,
    token: str | None,
    control_tcp_port: int | None = None,
    video_transport: str | None = None,
    video_codec: str | None = None,
    video_mode: str | None = None,
) -> tuple[socket.socket, threading.Thread]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp.bind(("0.0.0.0", discover_port))
    except OSError as e:
        log.error("UDP discovery: не удалось занять порт %s: %s", discover_port, e)
        raise
    log.info("UDP discovery: слушаем 0.0.0.0:%s (ответы на handshake)", discover_port)
    th = threading.Thread(
        target=_discovery_responder_loop,
        args=(udp, tcp_port, http_port, control_tcp_port, token, video_transport, video_codec, video_mode),
        daemon=True,
    )
    th.start()
    return udp, th
