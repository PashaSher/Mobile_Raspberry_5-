#!/usr/bin/env python3
"""
Скрипт для Raspberry Pi: передача видео с камеры (CSI/USB через libcamera) по TCP (MJPEG)
и UDP discovery (handshake в LAN). Запускайте на Pi под Raspberry Pi OS (или совместимой системе).

Слушать сеть и стримить после подключения клиента (типичный режим на Pi):
  python stream_camera.py send --listen --port 5000 --no-set-fps

По умолчанию на Raspberry Pi выбирается захват через picamera2 (libcamera). Явно:
  python stream_camera.py send --listen --port 5000 --capture picamera2 --no-set-fps

Передатчик сам ищет приёмник по UDP и подключается к нему:
  python stream_camera.py send --host auto

Или явный IP приёмника:
  python stream_camera.py send --host 192.168.1.50 --port 5000

Утилита Wi‑Fi (nmcli на Pi):
  python stream_camera.py wifi-scan

Протокол для приложения на другом устройстве (ПК и т.д.)
--------------------------------------------------------
TCP (порт по умолчанию 5000): поток кадров. Каждый кадр — 4 байта big-endian uint32
длина JPEG, затем ровно столько байт сжатого JPEG.

UDP broadcast, порт 37020 (по умолчанию): запрос discover от клиента (JSON):
  {"v":1,"cmd":"discover","token":"<строка или пусто>"}
Ответ от Pi (send --listen с включённым discovery):
  {"v":1,"cmd":"hello","tcp":5000,"name":"<hostname>","http":null}
Поле http зарезервировано; можно игнорировать.

Логи: --log-level DEBUG или -v. Дата/время на кадре: send ... --timestamp
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time

# UDP discovery (handshake в локальной сети после подключения к Wi‑Fi)
DISCOVERY_PORT_DEFAULT = 37020
DISCOVERY_VERSION = 1
DISCOVERY_REQ = "discover"
DISCOVERY_RSP = "hello"

# Очередь отправки TCP: при медленном приёмнике ядро не держит неограниченный объём RAM.
_STREAM_SNDBUF = 256 * 1024

log = logging.getLogger("camstream")


def _tune_stream_socket(sock: socket.socket) -> None:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _STREAM_SNDBUF)
    except OSError:
        pass


def _send_jpeg_frame(sock: socket.socket, payload: bytes) -> None:
    """Без склейки header+payload — меньше пиковых аллокаций на кадр."""
    sock.sendall(struct.pack(">I", len(payload)))
    sock.sendall(payload)


def _is_raspberry_pi() -> bool:
    """Определение платы по device-tree (работает на Raspberry Pi OS)."""
    try:
        with open("/proc/device-tree/model", "rb") as f:
            return b"Raspberry Pi" in f.read()
    except OSError:
        return False


def _default_capture_mode() -> str:
    """На Raspberry Pi по умолчанию libcamera (picamera2); иначе — перебор OpenCV."""
    return "picamera2" if _is_raspberry_pi() else "auto"


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
    Шлёт UDP broadcast и собирает ответы на handshake (discover).
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


def _frame_looks_valid(frame: object | None) -> bool:
    if frame is None:
        return False
    try:
        shape = getattr(frame, "shape", None)
        if shape is None or len(shape) < 2:
            return False
        h, w = int(shape[0]), int(shape[1])
        return h >= 8 and w >= 8
    except Exception:
        return False


def _warmup_camera(cap, max_tries: int = 45) -> tuple[bool, object | None]:
    import cv2

    for _ in range(max_tries):
        ok, frame = cap.read()
        if ok and _frame_looks_valid(frame):
            return True, frame
        time.sleep(0.05)
    return False, None


def _ensure_libcamera_on_sys_path() -> None:
    """venv без --system-site-packages не видит python3-libcamera из apt (Raspberry Pi OS)."""
    try:
        import libcamera  # noqa: F401
        return
    except ImportError:
        pass
    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    for root in (
        f"/usr/lib/python{ver}/dist-packages",
        "/usr/lib/python3/dist-packages",
    ):
        if os.path.isdir(os.path.join(root, "libcamera")) and root not in sys.path:
            sys.path.insert(0, root)
            return


def _picamera2_stream_to_socket(
    sock: socket.socket,
    width: int,
    height: int,
    jpeg_quality: int,
    overlay_timestamp: bool,
) -> None:
    """Захват через libcamera (picamera2) — на Pi 5 OpenCV/V4L2 часто не отдаёт кадры."""
    _ensure_libcamera_on_sys_path()
    try:
        from picamera2 import Picamera2
    except ImportError:
        log.error(
            "Нужны python3-libcamera и picamera2: sudo apt install -y python3-libcamera; "
            "pip install picamera2 (для сборки python-prctl: sudo apt install -y libcap2-dev)."
        )
        raise

    import cv2
    import numpy as np

    try:
        cv2.setNumThreads(1)
    except Exception:
        pass

    w = max(64, int(width))
    h = max(64, int(height))
    w = (w // 2) * 2
    h = (h // 2) * 2

    picam2 = Picamera2()
    cfg = picam2.create_video_configuration(
        main={"size": (w, h), "format": "RGB888"},
    )
    try:
        picam2.configure(cfg)
    except Exception as e:
        log.warning("picamera2: конфиг %dx%d не подошёл (%s), пробуем 640x480", w, h, e)
        w, h = 640, 480
        cfg = picam2.create_video_configuration(
            main={"size": (w, h), "format": "RGB888"},
        )
        picam2.configure(cfg)

    picam2.start()
    log.info("picamera2: камера запущена %dx%d (libcamera)", w, h)
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality]
    try:
        import simplejpeg  # type: ignore[import-untyped]

        _simplejpeg_ok = True
    except ImportError:
        simplejpeg = None  # type: ignore[misc, assignment]
        _simplejpeg_ok = False
    n = 0
    last_stat = time.monotonic()
    try:
        while True:
            frame = picam2.capture_array("main")
            if not frame.flags["C_CONTIGUOUS"]:
                frame = np.ascontiguousarray(frame)
            if frame.ndim == 2:
                frame_bgr = cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
                _draw_timestamp_on_frame(frame_bgr, overlay_timestamp)
                ok, jpeg = cv2.imencode(".jpg", frame_bgr, encode_params)
                if not ok:
                    continue
                payload = jpeg.tobytes()
            elif frame.shape[2] >= 3:
                # Формат «RGB888» от libcamera на Pi в памяти совпадает с порядком каналов BGR для OpenCV/JPEG.
                # Лишний RGB→BGR давал перепутанные красный и синий.
                bgr = np.ascontiguousarray(frame[:, :, :3])
                if overlay_timestamp:
                    frame_bgr = bgr
                    _draw_timestamp_on_frame(frame_bgr, overlay_timestamp)
                    ok, jpeg = cv2.imencode(".jpg", frame_bgr, encode_params)
                    if not ok:
                        continue
                    payload = jpeg.tobytes()
                elif _simplejpeg_ok:
                    payload = simplejpeg.encode_jpeg(
                        bgr,
                        quality=int(max(1, min(100, jpeg_quality))),
                        colorspace="BGR",
                    )
                else:
                    ok, jpeg = cv2.imencode(".jpg", bgr, encode_params)
                    if not ok:
                        continue
                    payload = jpeg.tobytes()
            else:
                continue
            plen = len(payload)
            _send_jpeg_frame(sock, payload)
            del payload
            n += 1
            if n == 1:
                log.info("picamera2: первый кадр отправлен (~%d байт JPEG)", plen)
            if n % 120 == 0:
                gc.collect()
            now = time.monotonic()
            if now - last_stat >= 5.0:
                log.info("picamera2: отправлено кадров за сессию: %d", n)
                last_stat = now
    finally:
        try:
            picam2.stop()
        except Exception:
            pass
        try:
            picam2.close()
        except Exception:
            pass


def _try_opencv_capture(
    camera: int,
    camera_device: str | None,
    capture_backend: str,
    width: int,
    height: int,
    fps: float,
    set_fps: bool,
) -> tuple[object | None, object | None]:
    import cv2

    attempts: list[tuple[str, object]] = []
    if camera_device:
        attempts.append(("path", cv2.VideoCapture(camera_device, cv2.CAP_V4L2)))
    if capture_backend == "v4l2":
        attempts.append(("v4l2", cv2.VideoCapture(camera, cv2.CAP_V4L2)))
    elif capture_backend == "default":
        attempts.append(("default", cv2.VideoCapture(camera)))
    else:
        attempts.append(("v4l2", cv2.VideoCapture(camera, cv2.CAP_V4L2)))
        attempts.append(("default", cv2.VideoCapture(camera)))

    for label, cap in attempts:
        if not cap.isOpened():
            cap.release()
            continue
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        if set_fps:
            cap.set(cv2.CAP_PROP_FPS, fps)
        ok, fr = _warmup_camera(cap)
        if ok and fr is not None:
            log.info("камера: OpenCV (%s), %dx%d @%.1f fps", label, width, height, fps)
            return cap, fr
        cap.release()
    return None, None


def _camera_stream_to_socket(
    sock: socket.socket,
    cap,
    jpeg_quality: int,
    overlay_timestamp: bool,
    first_frame: object | None = None,
) -> None:
    import cv2

    try:
        cv2.setNumThreads(1)
    except Exception:
        pass

    if first_frame is not None:
        ok, frame = True, first_frame
    else:
        ok, frame = _warmup_camera(cap)
    if not ok or frame is None:
        log.warning("камера: нет валидного кадра после прогрева")
        return

    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality]
    n = 0
    last_stat = time.monotonic()
    while True:
        _draw_timestamp_on_frame(frame, overlay_timestamp)
        ok, jpeg = cv2.imencode(".jpg", frame, encode_params)
        if not ok:
            log.debug("камера: пропуск кадра (imencode failed)")
            ok, frame = cap.read()
            if not ok or not _frame_looks_valid(frame):
                log.warning("камера: кадр не прочитан, конец стрима (отправлено кадров: %d)", n)
                break
            continue
        payload = jpeg.tobytes()
        plen = len(payload)
        _send_jpeg_frame(sock, payload)
        del payload
        n += 1
        if n == 1:
            log.info(
                "камера: первый кадр отправлен (~%d байт JPEG)%s",
                plen,
                " с датой/временем" if overlay_timestamp else "",
            )
        if n % 120 == 0:
            gc.collect()
        now = time.monotonic()
        if now - last_stat >= 5.0:
            log.info("камера: отправлено кадров за сессию: %d", n)
            last_stat = now

        ok, frame = cap.read()
        if not ok or not _frame_looks_valid(frame):
            log.warning("камера: кадр не прочитан, конец стрима (отправлено кадров: %d)", n)
            break


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
    camera_device: str | None,
    capture_backend: str,
    set_fps: bool,
    capture_mode: str,
) -> None:
    """
    Пассивный режим для автозапуска на Pi: UDP discovery + ожидание TCP,
    после accept открывается камера и идёт тот же поток MJPEG.
    """
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

    log.info("send: режим захвата=%s", capture_mode)

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
        _tune_stream_socket(conn)
        log.info("TCP: входящее подключение с %s:%s", addr[0], addr[1])

        if capture_mode == "picamera2":
            log.info("камера: режим picamera2 (libcamera), %dx%d", width, height)
            try:
                _picamera2_stream_to_socket(conn, width, height, jpeg_quality, overlay_timestamp)
            except BrokenPipeError:
                log.warning("TCP: клиент отключился (BrokenPipe)")
            except ImportError:
                log.error(
                    "Установите: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
                )
            finally:
                conn.close()
                log.info("сессия завершена, снова ожидание клиента на TCP %s ...", tcp_port)
            continue

        cap, first_fr = _try_opencv_capture(
            camera, camera_device, capture_backend, width, height, fps, set_fps
        )
        if cap is None and capture_mode == "auto":
            log.info("OpenCV не дал кадр — переключение на picamera2 (типично для Pi 5 + libcamera)")
            try:
                _picamera2_stream_to_socket(conn, width, height, jpeg_quality, overlay_timestamp)
            except BrokenPipeError:
                log.warning("TCP: клиент отключился (BrokenPipe)")
            except ImportError:
                log.error(
                    "Установите: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
                )
            finally:
                conn.close()
                log.info("сессия завершена, снова ожидание клиента на TCP %s ...", tcp_port)
            continue

        if cap is None:
            log.error(
                "камера: OpenCV не дал кадр. На Pi 5: --capture picamera2 или --capture auto, "
                "pip install picamera2 и python3-libcamera."
            )
            conn.close()
            continue

        try:
            _camera_stream_to_socket(conn, cap, jpeg_quality, overlay_timestamp, first_fr)
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
    camera_device: str | None,
    capture_backend: str,
    set_fps: bool,
    capture_mode: str,
) -> None:
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
            camera_device,
            capture_backend,
            set_fps,
            capture_mode,
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
                    "По UDP никто не ответил на discover. На ПК должно быть приложение с тем же портом handshake "
                    "или укажите IP вручную: --host <адрес>. Порт discovery: %s.",
                    discover_port,
                )
                sys.exit(1)
            log.warning(
                "Ответа discover нет, повтор через %.1f с (Ctrl+C — выход) ...",
                discover_loop_interval,
            )
            time.sleep(discover_loop_interval)

        if discover_index < 0 or discover_index >= len(peers):
            log.error("Индекс %s вне диапазона (найдено %d).", discover_index, len(peers))
            sys.exit(1)
        if len(peers) > 1:
            log.info("Найдено несколько ответов discover (см. --discover-index):")
            for i, p in enumerate(peers):
                ip_i, tcp_i, http_i, name_i = p
                extra = f" ({name_i})" if name_i else ""
                http_s = f" http={http_i}" if http_i is not None else ""
                log.info("  [%d] %s tcp=%s%s%s", i, ip_i, tcp_i, http_s, extra)
        ip, tcp_p, http_p, name = peers[discover_index]
        host = ip
        port = tcp_p
        log.info("Выбран хост #%d: %s:%s%s", discover_index, host, port, f" ({name})" if name else "")
        if http_p is not None:
            log.info("Просмотр в браузере: http://%s:%s/", host, http_p)

    log.info("send: режим захвата=%s", capture_mode)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _tune_stream_socket(sock)
    log.info("TCP: подключение к %s:%s ...", host, port)
    try:
        sock.connect((host, port))
    except OSError as e:
        log.error("TCP: подключение к %s:%s не удалось: %s", host, port, e)
        sys.exit(1)

    log.info("TCP: соединение установлено, стрим активен (Ctrl+C — выход)")

    if capture_mode == "picamera2":
        try:
            _picamera2_stream_to_socket(sock, width, height, jpeg_quality, overlay_timestamp)
        except BrokenPipeError:
            log.warning("TCP: соединение разорвано приёмником")
        except ImportError:
            log.error(
                "Установите: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
            )
        finally:
            sock.close()
            log.info("send: завершено")
        return

    cap, first_fr = _try_opencv_capture(
        camera, camera_device, capture_backend, width, height, fps, set_fps
    )
    if cap is not None:
        try:
            _camera_stream_to_socket(sock, cap, jpeg_quality, overlay_timestamp, first_fr)
        except BrokenPipeError:
            log.warning("TCP: соединение разорвано приёмником")
        finally:
            cap.release()
            sock.close()
            log.info("send: камера и сокет закрыты")
        return

    if capture_mode == "opencv":
        log.error("камера: OpenCV не дал кадр (попробуйте --capture auto или picamera2)")
        sock.close()
        sys.exit(1)

    log.info("OpenCV не дал кадр — пробуем picamera2 (libcamera) …")
    try:
        _picamera2_stream_to_socket(sock, width, height, jpeg_quality, overlay_timestamp)
    except BrokenPipeError:
        log.warning("TCP: соединение разорвано приёмником")
    except ImportError:
        log.error(
            "Установите: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
        )
    finally:
        sock.close()
        log.info("send: завершено")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Raspberry Pi: передача видео с камеры по TCP (MJPEG) + UDP discovery"
    )
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

    p_send = sub.add_parser("send", help="Стрим камеры Raspberry Pi")
    p_send.add_argument(
        "--host",
        default="auto",
        help="IP приёмника в LAN или auto — поиск по UDP (приложение на ПК должно отвечать на discover)",
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
        help="UDP-порт handshake (тот же, что слушает ваше приложение на ПК)",
    )
    p_send.add_argument(
        "--discover-token",
        default=None,
        help="Секрет для UDP discover (должен совпадать с клиентом на ПК)",
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
        help="Если найдено несколько ответов discover — номер в списке (0 по умолчанию)",
    )
    p_send.add_argument(
        "--discover-loop",
        action="store_true",
        help="Повторять поиск, пока по UDP не появится приёмник",
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
    p_send.add_argument(
        "--camera-device",
        default=None,
        metavar="PATH",
        help="Явный путь V4L2, напр. /dev/video0",
    )
    p_send.add_argument(
        "--capture-backend",
        choices=["auto", "v4l2", "default"],
        default="auto",
        help="Способ открытия камеры в OpenCV (auto перебирает варианты)",
    )
    p_send.add_argument(
        "--no-set-fps",
        action="store_true",
        help="Не задавать CAP_PROP_FPS (на libcamera иногда мешает)",
    )
    p_send.add_argument(
        "--capture",
        choices=["auto", "opencv", "picamera2"],
        default=_default_capture_mode(),
        help="Захват: на Raspberry Pi по умолчанию picamera2; auto — OpenCV, при неудаче picamera2; opencv — только OpenCV",
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
            args.camera_device,
            args.capture_backend,
            not args.no_set_fps,
            args.capture,
        )
        return


if __name__ == "__main__":
    main()
