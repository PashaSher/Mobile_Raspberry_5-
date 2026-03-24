#!/usr/bin/env python3
"""
Видеопоток с камеры на другой ПК / Raspberry Pi по локальной сети (Wi‑Fi).

Схема: приёмник слушает TCP-порт, передатчик подключается к IP приёмника и шлёт MJPEG.

Приёмник (картинка в браузере, без X11):
  python stream_camera.py receive --port 5000 --http 8080

Передатчик с автопоиском приёмника в той же Wi‑Fi сети (UDP handshake):
  python stream_camera.py send --host auto

Передатчик с явным IP:
  python stream_camera.py send --host 192.168.1.50 --port 5000

Автозапуск на Raspberry с камерой (ждёт handshake и TCP, потом стрим):
  python stream_camera.py send --listen --port 5000

Просмотр на ПК, подключение к Pi (receive как клиент):
  python stream_camera.py receive --http 8080 --peer auto

Список Wi‑Fi сетей (если установлен nmcli):
  python stream_camera.py wifi-scan

Окно OpenCV (нужен opencv-python с GTK, не headless):
  python stream_camera.py receive --port 5000 --gui

Логи в консоль (удобно по SSH): --log-level DEBUG или -v
Дата/время на кадре (на стороне камеры): send ... --timestamp

SSH и стрим с одного ПК: да — SSH (порт 22) и видео (TCP/HTTP/UDP) не мешают друг другу.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# UDP discovery (handshake в локальной сети после подключения к Wi‑Fi)
DISCOVERY_PORT_DEFAULT = 37020
DISCOVERY_VERSION = 1
DISCOVERY_REQ = "discover"
DISCOVERY_RSP = "hello"

log = logging.getLogger("camstream")


def setup_logging(level: int) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    h = logging.StreamHandler(sys.stderr)
    h.setLevel(level)
    h.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    root.addHandler(h)


# --- приём TCP: общий буфер последнего JPEG ---

_frame_lock = threading.Lock()
_latest_jpeg: bytes | None = None


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


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
) -> list[tuple[str, int, int | None, str | None]]:
    """
    Шлёт UDP broadcast и собирает ответы приёмников.
    Возвращает список (ip, tcp_port, http_port|None, name).
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
    seen: set[tuple[str, int, int | None]] = set()
    out: list[tuple[str, int, int | None, str | None]] = []

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
        name = msg.get("name")
        key = (ip, tcp_p, http_p)
        if key in seen:
            continue
        seen.add(key)
        out.append((ip, tcp_p, http_p, name if isinstance(name, str) else None))
        log.info(
            "discovery: ответ от %s tcp=%s http=%s name=%s",
            ip,
            tcp_p,
            http_p,
            name or "—",
        )

    sock.close()
    log.info("discovery: итого уникальных ответов: %d", len(out))
    return out


def _discovery_responder_loop(
    udp_sock: socket.socket,
    tcp_port: int,
    http_port: int | None,
    token: str | None,
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
        args=(udp, tcp_port, http_port, token),
        daemon=True,
    )
    th.start()
    return udp, th


def run_wifi_scan() -> None:
    log.info("wifi-scan: запуск nmcli ...")
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except FileNotFoundError:
        log.error("nmcli не найден. Установите NetworkManager или подключайтесь к Wi‑Fi вручную.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("Таймаут сканирования Wi‑Fi.")
        sys.exit(1)
    if r.returncode != 0:
        log.error("nmcli: %s", r.stderr or "ошибка")
        sys.exit(1)
    lines = [ln for ln in r.stdout.strip().splitlines() if ln.strip()]
    if not lines:
        log.warning("Сетей не найдено (возможно, Wi‑Fi выключён).")
        return
    log.info("SSID : SIGNAL : SECURITY (nmcli)")
    for ln in lines:
        log.info("%s", ln)


def _tcp_ingest_loop(conn: socket.socket) -> None:
    global _latest_jpeg
    n = 0
    last_stat = time.monotonic()
    while True:
        hdr = recv_exact(conn, 4)
        if hdr is None:
            log.info("приём: соединение закрыто или заголовок не получен (кадров: %d)", n)
            break
        (length,) = struct.unpack(">I", hdr)
        if length > 50 * 1024 * 1024:
            log.warning("приём: подозрительный размер кадра %d, выход", length)
            break
        data = recv_exact(conn, length)
        if data is None or len(data) != length:
            log.info("приём: обрыв данных (кадров: %d)", n)
            break
        with _frame_lock:
            _latest_jpeg = data
        n += 1
        if n == 1:
            log.info("приём: первый кадр получен (~%d байт JPEG)", len(data))
        now = time.monotonic()
        if now - last_stat >= 5.0:
            log.info("приём: получено кадров за сессию: %d", n)
            last_stat = now


def _draw_timestamp_on_frame(frame, enabled: bool) -> None:
    if not enabled:
        return
    import cv2
    from datetime import datetime

    text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(
        frame,
        text,
        (8, 26),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.6,
        (0, 255, 64),
        2,
        cv2.LINE_AA,
    )


def _camera_stream_to_socket(
    sock: socket.socket,
    cap,
    jpeg_quality: int,
    overlay_timestamp: bool,
) -> None:
    import cv2

    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality]
    n = 0
    last_stat = time.monotonic()
    while True:
        ok, frame = cap.read()
        if not ok:
            log.warning("камера: кадр не прочитан, конец стрима (отправлено кадров: %d)", n)
            break
        _draw_timestamp_on_frame(frame, overlay_timestamp)
        ok, jpeg = cv2.imencode(".jpg", frame, encode_params)
        if not ok:
            log.debug("камера: пропуск кадра (imencode failed)")
            continue
        payload = jpeg.tobytes()
        header = struct.pack(">I", len(payload))
        sock.sendall(header + payload)
        n += 1
        if n == 1:
            log.info("камера: первый кадр отправлен (~%d байт JPEG)%s", len(payload), " с датой/временем" if overlay_timestamp else "")
        now = time.monotonic()
        if now - last_stat >= 5.0:
            log.info("камера: отправлено кадров за сессию: %d", n)
            last_stat = now


def run_send_listen(
    tcp_port: int,
    camera: int,
    width: int,
    height: int,
    fps: float,
    jpeg_quality: int,
    discover_port: int | None,
    discover_token: str | None,
    http_advertise: int | None,
    overlay_timestamp: bool,
) -> None:
    """
    Пассивный режим для автозапуска на Pi: UDP discovery + ожидание TCP,
    после accept открывается камера и идёт тот же поток MJPEG.
    """
    import cv2

    if discover_port is not None:
        try:
            _start_discovery_responder(discover_port, tcp_port, http_advertise, discover_token)
        except OSError:
            sys.exit(1)
        log.info(
            "режим listen: UDP discovery на порту %s, ждём handshake в LAN%s",
            discover_port,
            " (нужен --discover-token на клиенте)" if discover_token else "",
        )
    else:
        log.info("режим listen: UDP discovery отключён (--no-discovery)")

    tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_srv.bind(("0.0.0.0", tcp_port))
    except OSError as e:
        log.error("TCP: не удалось bind 0.0.0.0:%s: %s", tcp_port, e)
        sys.exit(1)
    tcp_srv.listen(5)
    log.info("TCP: слушаем 0.0.0.0:%s, ждём клиента (Ctrl+C — выход)", tcp_port)

    while True:
        conn, addr = tcp_srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log.info("TCP: входящее подключение с %s:%s", addr[0], addr[1])

        cap = cv2.VideoCapture(camera, cv2.CAP_V4L2)
        if not cap.isOpened():
            cap = cv2.VideoCapture(camera)
        if not cap.isOpened():
            log.error("камера: устройство %s недоступно, закрываем сокет клиента", camera)
            conn.close()
            continue

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        cap.set(cv2.CAP_PROP_FPS, fps)
        log.info(
            "камера: открыта %s, %dx%d @%.1f fps, JPEG %d, timestamp=%s",
            camera,
            width,
            height,
            fps,
            jpeg_quality,
            overlay_timestamp,
        )

        try:
            _camera_stream_to_socket(conn, cap, jpeg_quality, overlay_timestamp)
        except BrokenPipeError:
            log.warning("TCP: клиент отключился (BrokenPipe)")
        finally:
            cap.release()
            conn.close()
            log.info("сессия завершена, снова ожидание клиента на TCP %s ...", tcp_port)


def run_send(
    host: str,
    port: int,
    camera: int,
    width: int,
    height: int,
    fps: float,
    jpeg_quality: int,
    discover_port: int,
    discover_token: str | None,
    discover_timeout: float,
    discover_index: int,
    discover_loop: bool,
    discover_loop_interval: float,
    listen: bool,
    listen_discover_port: int | None,
    listen_http_advertise: int | None,
    overlay_timestamp: bool,
) -> None:
    import cv2

    if listen:
        run_send_listen(
            port,
            camera,
            width,
            height,
            fps,
            jpeg_quality,
            listen_discover_port,
            discover_token,
            listen_http_advertise,
            overlay_timestamp,
        )
        return

    use_auto = host.strip().lower() in ("auto", "discover")
    if use_auto:
        tok = discover_token or ""
        while True:
            peers = discover_receivers(discover_port, tok, discover_timeout)
            if peers:
                break
            if not discover_loop:
                log.error(
                    "Приёмник не найден по UDP. Запустите receive на другой машине в той же Wi‑Fi сети "
                    "или укажите IP: --host <адрес>. Порт discovery: %s.",
                    discover_port,
                )
                sys.exit(1)
            log.warning(
                "Приёмника нет, повтор через %.1f с (Ctrl+C — выход) ...",
                discover_loop_interval,
            )
            time.sleep(discover_loop_interval)

        if discover_index < 0 or discover_index >= len(peers):
            log.error("Индекс %s вне диапазона (найдено %d).", discover_index, len(peers))
            sys.exit(1)
        if len(peers) > 1:
            log.info("Найдено несколько приёмников (см. --discover-index):")
            for i, p in enumerate(peers):
                ip_i, tcp_i, http_i, name_i = p
                extra = f" ({name_i})" if name_i else ""
                http_s = f" http={http_i}" if http_i is not None else ""
                log.info("  [%d] %s tcp=%s%s%s", i, ip_i, tcp_i, http_s, extra)
        ip, tcp_p, http_p, name = peers[discover_index]
        host = ip
        port = tcp_p
        log.info("Выбран приёмник #%d: %s:%s%s", discover_index, host, port, f" ({name})" if name else "")
        if http_p is not None:
            log.info("Просмотр в браузере: http://%s:%s/", host, http_p)

    log.info(
        "send: открытие камеры %s, %dx%d @%.1f fps, JPEG %d, timestamp=%s",
        camera,
        width,
        height,
        fps,
        jpeg_quality,
        overlay_timestamp,
    )
    cap = cv2.VideoCapture(camera, cv2.CAP_V4L2)
    if not cap.isOpened():
        cap = cv2.VideoCapture(camera)

    if not cap.isOpened():
        log.error("камера: не удалось открыть устройство %s", camera)
        sys.exit(1)

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
    cap.set(cv2.CAP_PROP_FPS, fps)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log.info("TCP: подключение к %s:%s ...", host, port)
    try:
        sock.connect((host, port))
    except OSError as e:
        log.error("TCP: подключение к %s:%s не удалось: %s", host, port, e)
        cap.release()
        sys.exit(1)

    log.info("TCP: соединение установлено, стрим активен (Ctrl+C — выход)")

    try:
        _camera_stream_to_socket(sock, cap, jpeg_quality, overlay_timestamp)
    except BrokenPipeError:
        log.warning("TCP: соединение разорвано приёмником")
    finally:
        cap.release()
        sock.close()
        log.info("send: камера и сокет закрыты")


def _make_mjpeg_handler(boundary_token: str) -> type[BaseHTTPRequestHandler]:
    b = boundary_token.encode("ascii")

    class MJPEGHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            msg = format % args if args else format
            log.info('HTTP %s "%s"', self.address_string(), msg.strip())

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                html = (
                    "<!DOCTYPE html><html><head><meta charset=utf-8>"
                    "<title>Камера</title><style>body{margin:0;background:#111;"
                    "display:flex;justify-content:center;align-items:center;"
                    "min-height:100vh}</style></head><body>"
                    '<img src="/stream" alt="поток" style="max-width:100%;height:auto" />'
                    "</body></html>"
                )
                data = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            if self.path != "/stream":
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header(
                "Content-Type",
                f"multipart/x-mixed-replace; boundary={boundary_token}",
            )
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            try:
                while True:
                    with _frame_lock:
                        jpeg = _latest_jpeg
                    if jpeg is None:
                        time.sleep(0.02)
                        continue
                    self.wfile.write(b"--" + b + b"\r\n")
                    self.wfile.write(b"Content-Type: image/jpeg\r\n")
                    self.wfile.write(f"Content-Length: {len(jpeg)}\r\n\r\n".encode())
                    self.wfile.write(jpeg)
                    self.wfile.write(b"\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

    return MJPEGHandler


def _resolve_peer_tcp(
    peer: str,
    tcp_port: int,
    discover_port: int,
    discover_token: str | None,
    discover_index: int,
    discover_timeout: float,
) -> tuple[str, int]:
    if peer.strip().lower() in ("auto", "discover"):
        tok = discover_token or ""
        peers = discover_receivers(discover_port, tok, discover_timeout)
        if not peers:
            log.error(
                "Устройство с камерой не найдено по UDP. На Pi: send --listen в той же сети или --peer <IP>."
            )
            sys.exit(1)
        if discover_index < 0 or discover_index >= len(peers):
            log.error("Индекс %s вне диапазона (найдено %d).", discover_index, len(peers))
            sys.exit(1)
        if len(peers) > 1:
            log.info("Найдено несколько устройств (см. --discover-index):")
            for i, p in enumerate(peers):
                ip_i, tcp_i, http_i, name_i = p
                extra = f" ({name_i})" if name_i else ""
                http_s = f" http={http_i}" if http_i is not None else ""
                log.info("  [%d] %s tcp=%s%s%s", i, ip_i, tcp_i, http_s, extra)
        ip, tcp_p, _, name = peers[discover_index]
        log.info("receive: цель %s:%s%s", ip, tcp_p, f" ({name})" if name else "")
        return ip, tcp_p
    return peer.strip(), tcp_port


def run_receive_http(
    tcp_port: int,
    http_port: int,
    discover_port: int | None,
    discover_token: str | None,
    peer: str | None,
    discover_index: int,
    discover_timeout: float,
) -> None:
    global _latest_jpeg

    if peer is None:
        log.info("receive: режим сервера (ждём входящий TCP поток с камеры)")
        if discover_port is not None:
            try:
                _start_discovery_responder(discover_port, tcp_port, http_port, discover_token)
            except OSError:
                sys.exit(1)
            log.info(
                "UDP discovery ответчик на порту %s%s",
                discover_port,
                " (токен на передатчике)" if discover_token else "",
            )

        tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_srv.bind(("0.0.0.0", tcp_port))
        tcp_srv.listen(1)
        log.info("TCP: ожидание камеры на 0.0.0.0:%s ...", tcp_port)

        handler = _make_mjpeg_handler("mjpegframe")
        httpd = ThreadingHTTPServer(("0.0.0.0", http_port), handler)
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()
        log.info("HTTP: веб-интерфейс http://<этот_IP>:%s/", http_port)

        conn, addr = tcp_srv.accept()
        tcp_srv.close()
        log.info("TCP: поток с камеры подключился с %s:%s", addr[0], addr[1])
    else:
        log.info("receive: режим клиента, peer=%s", peer)
        dp = discover_port if discover_port is not None else DISCOVERY_PORT_DEFAULT
        rh, rport = _resolve_peer_tcp(
            peer, tcp_port, dp, discover_token, discover_index, discover_timeout
        )
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log.info("TCP: соединение с %s:%s ...", rh, rport)
        try:
            conn.connect((rh, rport))
        except OSError as e:
            log.error("TCP к %s:%s: %s", rh, rport, e)
            sys.exit(1)
        log.info("TCP: подключено к потоку %s:%s", rh, rport)

        with _frame_lock:
            _latest_jpeg = None

        handler = _make_mjpeg_handler("mjpegframe")
        httpd = ThreadingHTTPServer(("0.0.0.0", http_port), handler)
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()
        log.info("HTTP: откройте http://127.0.0.1:%s/ или http://<этот_ПК>:%s/", http_port, http_port)

    log.info("приём: поток декодирования JPEG запущен")
    ingest = threading.Thread(target=_tcp_ingest_loop, args=(conn,), daemon=True)
    ingest.start()
    ingest.join()
    conn.close()
    httpd.shutdown()
    log.info("receive: HTTP и TCP закрыты")


def run_receive_gui(
    tcp_port: int,
    camera_label: str,
    discover_port: int | None,
    discover_token: str | None,
    peer: str | None,
    discover_index: int,
    discover_timeout: float,
) -> None:
    import cv2
    import numpy as np

    if peer is None:
        log.info("receive/gui: режим сервера")
        if discover_port is not None:
            try:
                _start_discovery_responder(discover_port, tcp_port, None, discover_token)
            except OSError:
                sys.exit(1)
            log.info(
                "UDP discovery на порту %s%s",
                discover_port,
                " (токен на передатчике)" if discover_token else "",
            )

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", tcp_port))
        server.listen(1)
        log.info("TCP: ожидание на 0.0.0.0:%s ...", tcp_port)

        conn, addr = server.accept()
        server.close()
        log.info("TCP: подключение с %s:%s", addr[0], addr[1])
    else:
        log.info("receive/gui: режим клиента, peer=%s", peer)
        dp = discover_port if discover_port is not None else DISCOVERY_PORT_DEFAULT
        rh, rport = _resolve_peer_tcp(
            peer, tcp_port, dp, discover_token, discover_index, discover_timeout
        )
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log.info("TCP: соединение с %s:%s ...", rh, rport)
        try:
            conn.connect((rh, rport))
        except OSError as e:
            log.error("TCP к %s:%s: %s", rh, rport, e)
            sys.exit(1)
        log.info("TCP: подключено к %s:%s", rh, rport)

    window = f"Поток {camera_label}"
    try:
        while True:
            hdr = recv_exact(conn, 4)
            if hdr is None:
                break
            (length,) = struct.unpack(">I", hdr)
            if length > 50 * 1024 * 1024:
                log.warning("Некорректный размер кадра %d", length)
                break
            data = recv_exact(conn, length)
            if data is None or len(data) != length:
                break
            arr = np.frombuffer(data, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is None:
                continue
            cv2.imshow(window, frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
    finally:
        conn.close()
        cv2.destroyAllWindows()


def main() -> None:
    parser = argparse.ArgumentParser(description="Стрим камеры по TCP (MJPEG)")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Логи в stderr (удобно смотреть по SSH)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Подробный вывод (-v = уровень DEBUG)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="Передатчик (камера на этой машине)")
    p_send.add_argument(
        "--host",
        default="auto",
        help="IP приёмника в LAN или auto — поиск по UDP (должен быть запущен receive)",
    )
    p_send.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP-порт приёмника (если не auto; при auto берётся из ответа discovery)",
    )
    p_send.add_argument("--camera", type=int, default=0, help="Индекс камеры (0 по умолчанию)")
    p_send.add_argument("--width", type=int, default=640)
    p_send.add_argument("--height", type=int, default=480)
    p_send.add_argument("--fps", type=float, default=25.0)
    p_send.add_argument("--jpeg-quality", type=int, default=80, help="1–100")
    p_send.add_argument(
        "--discover-port",
        type=int,
        default=DISCOVERY_PORT_DEFAULT,
        help="UDP-порт handshake (тот же, что у receive)",
    )
    p_send.add_argument(
        "--discover-token",
        default=None,
        help="Тот же секрет, что задан на receive (если используется)",
    )
    p_send.add_argument(
        "--discover-timeout",
        type=float,
        default=5.0,
        help="Секунд ожидания ответов за один раунд discovery",
    )
    p_send.add_argument(
        "--discover-index",
        type=int,
        default=0,
        help="Если найдено несколько приёмников — номер в списке (0 по умолчанию)",
    )
    p_send.add_argument(
        "--discover-loop",
        action="store_true",
        help="Повторять поиск, пока приёмник не появится в сети",
    )
    p_send.add_argument(
        "--discover-loop-interval",
        type=float,
        default=3.0,
        help="Пауза между попытками при --discover-loop",
    )
    p_send.add_argument(
        "--listen",
        action="store_true",
        help="Слушать TCP на этой машине: UDP discovery + ожидание клиента, затем камера (для автозапуска на Pi)",
    )
    p_send.add_argument(
        "--no-discovery",
        action="store_true",
        help="При --listen: не отвечать на UDP discovery (только прямой TCP по IP)",
    )
    p_send.add_argument(
        "--timestamp",
        action="store_true",
        help="Рисовать дату и время на каждом кадре (на стороне камеры, до сжатия JPEG)",
    )

    p_recv = sub.add_parser("receive", help="Приёмник")
    p_recv.add_argument("--port", type=int, default=5000, help="TCP-порт для подключения камеры")
    p_recv.add_argument(
        "--http",
        type=int,
        nargs="?",
        const=8080,
        default=None,
        metavar="PORT",
        help="Показ в браузере (порт HTTP, по умолчанию 8080). Рекомендуется для Pi без монитора.",
    )
    p_recv.add_argument(
        "--gui",
        action="store_true",
        help="Окно OpenCV (нужен opencv-python с поддержкой GUI, не headless)",
    )
    p_recv.add_argument("--title", default="камера", help="Заголовок окна (только с --gui)")
    p_recv.add_argument(
        "--discover-port",
        type=int,
        default=DISCOVERY_PORT_DEFAULT,
        help="UDP-порт для ответа на запросы discover (0 = отключить)",
    )
    p_recv.add_argument(
        "--no-discovery",
        action="store_true",
        help="Не отвечать на UDP discovery (только ручной IP)",
    )
    p_recv.add_argument(
        "--discover-token",
        default=None,
        help="Секрет: отвечать только клиентам с тем же токеном",
    )
    p_recv.add_argument(
        "--peer",
        default=None,
        metavar="HOST_OR_auto",
        help="Подключиться к хосту с камерой (IP или auto). Иначе режим сервера (ждёт send).",
    )
    p_recv.add_argument(
        "--discover-index",
        type=int,
        default=0,
        help="При --peer auto — номер устройства в списке discovery",
    )
    p_recv.add_argument(
        "--discover-timeout",
        type=float,
        default=5.0,
        help="Таймаут discovery при --peer auto",
    )

    sub.add_parser("wifi-scan", help="Показать доступные Wi‑Fi сети (nmcli)")

    args = parser.parse_args()
    level = logging.DEBUG if args.verbose else getattr(logging, args.log_level)
    setup_logging(level)
    log.info("camstream: команда=%s, уровень логов=%s", args.cmd, logging.getLevelName(level))

    if args.cmd == "wifi-scan":
        run_wifi_scan()
        return

    if args.cmd == "send":
        if args.listen and args.host.strip().lower() not in ("auto", "discover"):
            print(
                "При --listen параметр --host не используется (клиенты подключаются к этому Pi).",
                file=sys.stderr,
            )
        if args.listen:
            listen_disc = None if args.no_discovery or args.discover_port == 0 else args.discover_port
        else:
            listen_disc = None
        run_send(
            args.host,
            args.port,
            args.camera,
            args.width,
            args.height,
            args.fps,
            args.jpeg_quality,
            args.discover_port,
            args.discover_token,
            args.discover_timeout,
            args.discover_index,
            args.discover_loop,
            args.discover_loop_interval,
            args.listen,
            listen_disc,
            None,
            args.timestamp,
        )
        return

    if args.gui and args.http is not None:
        print("Используйте только один режим: --http или --gui", file=sys.stderr)
        sys.exit(1)

    disc_port = None if args.no_discovery or args.discover_port == 0 else args.discover_port
    disc_tok = args.discover_token if args.discover_token else None

    if args.gui:
        run_receive_gui(
            args.port,
            args.title,
            disc_port,
            disc_tok,
            args.peer,
            args.discover_index,
            args.discover_timeout,
        )
    elif args.http is not None:
        run_receive_http(
            args.port,
            args.http,
            disc_port,
            disc_tok,
            args.peer,
            args.discover_index,
            args.discover_timeout,
        )
    else:
        print(
            "Укажите режим: --http [ПОРТ] (браузер) или --gui (окно OpenCV).\n"
            "Пример: python stream_camera.py receive --port 5000 --http 8080",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
