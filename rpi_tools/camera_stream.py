"""Камера Raspberry Pi: захват (OpenCV / picamera2), MJPEG по TCP, режим listen + discovery."""

from __future__ import annotations

import errno
import gc
import io
import logging
import os
import queue
import socket
import struct
import sys
import threading
import time

from rpi_tools.config import (
    JPEG_TCP_QUEUE_DEPTH_DEFAULT,
    ROMEO_ADC_DEFAULT_CHANNEL,
    ROMEO_BATTERY_MONITOR_USE_VBAT,
    ROMEO_USB_PORT,
    _STREAM_SNDBUF,
)
from rpi_tools.discovery import _start_discovery_responder, discover_receivers
from rpi_tools.romeo_control_server import start_romeo_control_server
from rpi_tools.errors import TcpBindError
from rpi_tools.romeo_usb import start_romeo_adc_monitor, start_romeo_led_heartbeat

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


_JPEG_TCP_QUEUE_SENTINEL = object()


class _TcpJpegSendPipeline:
    """
    Отправка кадров в отдельном потоке: поток кодирования не ждёт медленный TCP приёмник.

    При переполнении очереди выбрасывается самый старый кадр (ниже задержка отображения при лаге сети/ПК).
    """

    __slots__ = ("_sock", "_q", "_stop", "_th")

    def __init__(self, sock: socket.socket, queue_depth: int) -> None:
        self._sock = sock
        self._q: queue.Queue | None = None
        self._stop: threading.Event | None = None
        self._th: threading.Thread | None = None
        d = int(queue_depth)
        if d <= 0:
            return
        self._q = queue.Queue(maxsize=max(1, d))
        self._stop = threading.Event()

        def _loop() -> None:
            assert self._q is not None and self._stop is not None
            while not self._stop.is_set():
                try:
                    item = self._q.get(timeout=0.25)
                except queue.Empty:
                    continue
                if item is _JPEG_TCP_QUEUE_SENTINEL:
                    break
                try:
                    _send_jpeg_frame(self._sock, item)
                except OSError:
                    self._stop.set()
                    break

        self._th = threading.Thread(target=_loop, name="jpeg-tcp-sender", daemon=True)
        self._th.start()

    def submit(self, payload: bytes) -> None:
        if self._q is None:
            _send_jpeg_frame(self._sock, payload)
            return
        assert self._stop is not None
        if self._stop.is_set():
            raise BrokenPipeError("jpeg-tcp-sender stopped")
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(payload)
            except queue.Full:
                pass

    def close(self) -> None:
        if self._th is None or self._q is None:
            return
        assert self._stop is not None
        self._stop.set()
        try:
            self._q.put_nowait(_JPEG_TCP_QUEUE_SENTINEL)
        except queue.Full:
            try:
                self._q.get_nowait()
                self._q.put_nowait(_JPEG_TCP_QUEUE_SENTINEL)
            except queue.Empty:
                pass
        self._th.join(timeout=3.0)


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


def _opencv_jpeg_encode_params(jpeg_quality: int) -> list[int]:
    """Параметры JPEG для OpenCV: 4:4:4, оптимизация таблиц, luma/chroma как у общего quality."""
    import cv2

    q = int(max(1, min(100, jpeg_quality)))
    params: list[int] = [
        int(cv2.IMWRITE_JPEG_QUALITY),
        q,
        int(cv2.IMWRITE_JPEG_CHROMA_QUALITY),
        q,
        int(cv2.IMWRITE_JPEG_LUMA_QUALITY),
        q,
        int(cv2.IMWRITE_JPEG_OPTIMIZE),
        1,
    ]
    if hasattr(cv2, "IMWRITE_JPEG_SAMPLING_FACTOR") and hasattr(cv2, "IMWRITE_JPEG_SAMPLING_FACTOR_444"):
        params.extend(
            (
                int(cv2.IMWRITE_JPEG_SAMPLING_FACTOR),
                int(cv2.IMWRITE_JPEG_SAMPLING_FACTOR_444),
            )
        )
    return params


def _picamera2_apply_quality_tuning(picam2: object) -> None:
    """Слегка повышаем резкость; ошибки игнорируем (разные драйверы / версии libcamera)."""
    try:
        picam2.set_controls({"Sharpness": 1.35})
    except Exception as exc:
        log.debug("picamera2: Sharpness не применён: %s", exc)
    try:
        from libcamera import controls

        minimal = getattr(
            getattr(controls, "draft", controls), "NoiseReductionModeEnum", None
        )
        if minimal is not None and hasattr(minimal, "Minimal"):
            picam2.set_controls({"NoiseReductionMode": minimal.Minimal})
    except Exception as exc:
        log.debug("picamera2: NoiseReductionMode не применён: %s", exc)


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
    fps: float,
    set_fps: bool,
    *,
    picamera_use_jpeg_encoder: bool = True,
    jpeg_chroma_subsampling: str = "422",
    jpeg_encoder_threads: int = 8,
    jpeg_fast_dct: bool = True,
    jpeg_tcp_queue_depth: int = JPEG_TCP_QUEUE_DEPTH_DEFAULT,
) -> None:
    """Захват libcamera: по умолчанию picamera2 JpegEncoder (MultiEncoder, несколько потоков simplejpeg). Иначе capture_array."""
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

    chroma = jpeg_chroma_subsampling.strip()
    if chroma not in ("444", "422", "420"):
        chroma = "422"

    picam2 = Picamera2()
    fps_ctl: dict | None = None
    if set_fps and fps > 0:
        fp = max(5.0, min(60.0, float(fps)))
        dur = max(5000, min(200000, int(round(1_000_000.0 / fp))))
        fps_ctl = {"FrameDurationLimits": (dur, dur)}

    cfg = picam2.create_video_configuration(
        main={"size": (w, h), "format": "RGB888"},
        buffer_count=6,
        controls=fps_ctl or {},
    )
    try:
        picam2.configure(cfg)
    except Exception as e:
        log.warning("picamera2: конфиг %dx%d не подошёл (%s), пробуем 640x480", w, h, e)
        w, h = 640, 480
        cfg = picam2.create_video_configuration(
            main={"size": (w, h), "format": "RGB888"},
            buffer_count=6,
            controls=fps_ctl or {},
        )
        picam2.configure(cfg)

    frame_period = (1.0 / max(5.0, min(60.0, float(fps)))) if (set_fps and fps > 0) else 0.0
    if frame_period > 0:
        log.info(
            "picamera2: целевой темп ~%.2f Hz (FrameDurationLimits%s)",
            1.0 / frame_period,
            " + пауза в запасном цикле" if not picamera_use_jpeg_encoder or overlay_timestamp else "",
        )

    jq = int(max(1, min(100, jpeg_quality)))
    enc_threads = max(1, min(16, int(jpeg_encoder_threads)))
    tcp_q = max(0, min(32, int(jpeg_tcp_queue_depth)))
    if tcp_q > 0:
        log.info(
            "TCP JPEG: отдельный поток отправки, очередь %d кадров (медленный ПК/Wi‑Fi — дроп старых, без блокировки кодера)",
            tcp_q,
        )

    use_encoder = picamera_use_jpeg_encoder and not overlay_timestamp
    if use_encoder:
        try:
            from picamera2.encoders import JpegEncoder
            from picamera2.outputs import FileOutput
        except ImportError:
            use_encoder = False

    if use_encoder:
        done = threading.Event()
        frames_sent = [0]
        enc_pipeline = _TcpJpegSendPipeline(sock, tcp_q)

        class _TcpJpegSink(io.BufferedIOBase):
            def writable(self) -> bool:
                return True

            def write(self, buf) -> int:
                try:
                    data = buf.tobytes() if isinstance(buf, memoryview) else bytes(buf)
                    enc_pipeline.submit(data)
                    frames_sent[0] += 1
                    if frames_sent[0] == 1:
                        log.info(
                            "picamera2: первый кадр (~%d байт) — JpegEncoder threads=%d chroma=%s q=%d",
                            len(data),
                            enc_threads,
                            chroma,
                            jq,
                        )
                    return len(buf)
                except OSError:
                    done.set()
                    raise
                except BrokenPipeError:
                    done.set()
                    raise

        sink = _TcpJpegSink()
        enc = JpegEncoder(
            num_threads=enc_threads,
            q=jq,
            colour_subsampling=chroma,
        )
        encoder_session_ok = False
        try:
            picam2.start_recording(enc, FileOutput(sink))
            _picamera2_apply_quality_tuning(picam2)
            log.info(
                "picamera2: поток через picamera2 JpegEncoder (как в официальном mjpeg_server.py), %dx%d",
                w,
                h,
            )
            try:
                while not done.wait(1.0):
                    pass
            except KeyboardInterrupt:
                pass
            encoder_session_ok = True
        except Exception as exc:
            log.warning("picamera2: JpegEncoder (%s), переход на запасной цикл capture_array", exc)
        finally:
            try:
                picam2.stop_recording()
            except Exception:
                pass
            enc_pipeline.close()

        if encoder_session_ok or frames_sent[0] > 0:
            try:
                picam2.close()
            except Exception:
                pass
            return

    encode_params = _opencv_jpeg_encode_params(jpeg_quality)
    try:
        import simplejpeg  # type: ignore[import-untyped]

        _simplejpeg_ok = True
    except ImportError:
        simplejpeg = None  # type: ignore[misc, assignment]
        _simplejpeg_ok = False

    picam2.start()
    _picamera2_apply_quality_tuning(picam2)
    log.info("picamera2: камера %dx%d (запасной путь capture_array + JPEG)", w, h)
    n = 0
    last_stat = time.monotonic()
    leg_pipeline = _TcpJpegSendPipeline(sock, tcp_q)
    try:
        while True:
            t_iter = time.monotonic()
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
                        quality=jq,
                        colorspace="BGR",
                        colorsubsampling=chroma,
                        fastdct=jpeg_fast_dct,
                    )
                else:
                    ok, jpeg = cv2.imencode(".jpg", bgr, encode_params)
                    if not ok:
                        continue
                    payload = jpeg.tobytes()
            else:
                continue
            plen = len(payload)
            try:
                leg_pipeline.submit(payload)
            except (OSError, BrokenPipeError):
                break
            del payload
            n += 1
            if frame_period > 0:
                elapsed = time.monotonic() - t_iter
                slack = frame_period - elapsed
                if slack > 0.0005:
                    time.sleep(slack)
            if n == 1:
                log.info("picamera2: первый кадр отправлен (~%d байт JPEG)", plen)
            if n % 120 == 0:
                gc.collect()
            now = time.monotonic()
            if now - last_stat >= 5.0:
                log.info("picamera2: отправлено кадров за сессию: %d", n)
                last_stat = now
    finally:
        leg_pipeline.close()
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
    jpeg_tcp_queue_depth: int = JPEG_TCP_QUEUE_DEPTH_DEFAULT,
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

    tcp_q = max(0, min(32, int(jpeg_tcp_queue_depth)))
    if tcp_q > 0:
        log.info(
            "TCP JPEG: отдельный поток отправки, очередь %d кадров (OpenCV захват)",
            tcp_q,
        )

    encode_params = _opencv_jpeg_encode_params(jpeg_quality)
    n = 0
    last_stat = time.monotonic()
    pipeline = _TcpJpegSendPipeline(sock, tcp_q)
    try:
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
            try:
                pipeline.submit(payload)
            except (OSError, BrokenPipeError):
                break
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
    finally:
        pipeline.close()


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
    romeo_control_port: int = 0,
    romeo_usb_port: str | None = None,
    romeo_baud: int = 115200,
    romeo_open_delay: float = 0.0,
    romeo_tank_speed: int = 200,
    romeo_turret_step: int | float | None = None,
    romeo_led_interval_sec: float = 5.0,
    romeo_adc_interval_sec: float = 0.0,
    picamera_use_jpeg_encoder: bool = True,
    jpeg_chroma_subsampling: str = "422",
    jpeg_encoder_threads: int = 8,
    jpeg_fast_dct: bool = True,
    jpeg_tcp_queue_depth: int = JPEG_TCP_QUEUE_DEPTH_DEFAULT,
) -> None:
    """
    Пассивный режим для автозапуска на Pi: UDP discovery + ожидание TCP,
    после accept открывается камера и идёт тот же поток MJPEG.
    """
    ctl_advertise = romeo_control_port if romeo_control_port > 0 else None
    if discover_port is not None:
        try:
            _start_discovery_responder(
                discover_port,
                tcp_port,
                http_advertise,
                discover_token,
                control_tcp_port=ctl_advertise,
            )
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

    if romeo_control_port > 0:
        usb = romeo_usb_port or ROMEO_USB_PORT
        start_romeo_control_server(
            romeo_control_port,
            romeo_port=usb,
            baud=romeo_baud,
            open_delay=romeo_open_delay,
            tank_speed=romeo_tank_speed,
            turret_step_default=romeo_turret_step,
        )

    tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_srv.bind(("0.0.0.0", tcp_port))
    except OSError as e:
        log.error("TCP: не удалось bind 0.0.0.0:%s: %s", tcp_port, e)
        en = getattr(e, "errno", None)
        if en == errno.EADDRINUSE or "Address already in use" in str(e):
            log.error(
                "Порт %s занят (часто предыдущий запуск не закрыт). Проверка: fuser -v %s/tcp "
                "или ss -tlnp '( sport = :%s )'; остановка: kill <pid> или sudo fuser -k %s/tcp",
                tcp_port,
                tcp_port,
                tcp_port,
                tcp_port,
            )
        raise TcpBindError from e
    tcp_srv.listen(5)
    log.info("TCP: слушаем 0.0.0.0:%s, ждём клиента (Ctrl+C — выход)", tcp_port)

    usb = romeo_usb_port or ROMEO_USB_PORT
    if romeo_led_interval_sec > 0:
        start_romeo_led_heartbeat(
            port=usb,
            baud=romeo_baud,
            interval_sec=float(romeo_led_interval_sec),
            open_delay=romeo_open_delay,
        )

    if romeo_adc_interval_sec > 0:
        start_romeo_adc_monitor(
            port=usb,
            baud=romeo_baud,
            interval_sec=float(romeo_adc_interval_sec),
            channel=ROMEO_ADC_DEFAULT_CHANNEL,
            open_delay=romeo_open_delay,
            use_vbat=ROMEO_BATTERY_MONITOR_USE_VBAT,
        )

    while True:
        conn, addr = tcp_srv.accept()
        _tune_stream_socket(conn)
        log.info("TCP: входящее подключение с %s:%s", addr[0], addr[1])

        if capture_mode == "picamera2":
            log.info("камера: режим picamera2 (libcamera), %dx%d", width, height)
            try:
                _picamera2_stream_to_socket(
                    conn,
                    width,
                    height,
                    jpeg_quality,
                    overlay_timestamp,
                    fps,
                    set_fps,
                    picamera_use_jpeg_encoder=picamera_use_jpeg_encoder,
                    jpeg_chroma_subsampling=jpeg_chroma_subsampling,
                    jpeg_encoder_threads=jpeg_encoder_threads,
                    jpeg_fast_dct=jpeg_fast_dct,
                    jpeg_tcp_queue_depth=jpeg_tcp_queue_depth,
                )
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
                _picamera2_stream_to_socket(
                    conn,
                    width,
                    height,
                    jpeg_quality,
                    overlay_timestamp,
                    fps,
                    set_fps,
                    picamera_use_jpeg_encoder=picamera_use_jpeg_encoder,
                    jpeg_chroma_subsampling=jpeg_chroma_subsampling,
                    jpeg_encoder_threads=jpeg_encoder_threads,
                    jpeg_fast_dct=jpeg_fast_dct,
                    jpeg_tcp_queue_depth=jpeg_tcp_queue_depth,
                )
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
            _camera_stream_to_socket(
                conn, cap, jpeg_quality, overlay_timestamp, first_fr, jpeg_tcp_queue_depth=jpeg_tcp_queue_depth
            )
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
    romeo_control_port: int = 0,
    romeo_usb_port: str | None = None,
    romeo_baud: int = 115200,
    romeo_open_delay: float = 0.0,
    romeo_tank_speed: int = 200,
    romeo_turret_step: int | float | None = None,
    romeo_led_interval_sec: float = 5.0,
    romeo_adc_interval_sec: float = 0.0,
    picamera_use_jpeg_encoder: bool = True,
    jpeg_chroma_subsampling: str = "422",
    jpeg_encoder_threads: int = 8,
    jpeg_fast_dct: bool = True,
    jpeg_tcp_queue_depth: int = JPEG_TCP_QUEUE_DEPTH_DEFAULT,
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
            romeo_control_port=romeo_control_port,
            romeo_usb_port=romeo_usb_port,
            romeo_baud=romeo_baud,
            romeo_open_delay=romeo_open_delay,
            romeo_tank_speed=romeo_tank_speed,
            romeo_turret_step=romeo_turret_step,
            romeo_led_interval_sec=romeo_led_interval_sec,
            romeo_adc_interval_sec=romeo_adc_interval_sec,
            picamera_use_jpeg_encoder=picamera_use_jpeg_encoder,
            jpeg_chroma_subsampling=jpeg_chroma_subsampling,
            jpeg_encoder_threads=jpeg_encoder_threads,
            jpeg_fast_dct=jpeg_fast_dct,
            jpeg_tcp_queue_depth=jpeg_tcp_queue_depth,
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
                ip_i, tcp_i, http_i, name_i, ctl_i = p
                extra = f" ({name_i})" if name_i else ""
                http_s = f" http={http_i}" if http_i is not None else ""
                ctl_s = f" control={ctl_i}" if ctl_i is not None else ""
                log.info("  [%d] %s tcp=%s%s%s%s", i, ip_i, tcp_i, http_s, ctl_s, extra)
        ip, tcp_p, http_p, name, ctl_p = peers[discover_index]
        host = ip
        port = tcp_p
        log.info("Выбран хост #%d: %s:%s%s", discover_index, host, port, f" ({name})" if name else "")
        if http_p is not None:
            log.info("Просмотр в браузере: http://%s:%s/", host, http_p)
        if ctl_p is not None:
            log.info("Romeo control (TCP с ПК на Pi): %s:%s", host, ctl_p)

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
            _picamera2_stream_to_socket(
                sock,
                width,
                height,
                jpeg_quality,
                overlay_timestamp,
                fps,
                set_fps,
                picamera_use_jpeg_encoder=picamera_use_jpeg_encoder,
                jpeg_chroma_subsampling=jpeg_chroma_subsampling,
                jpeg_encoder_threads=jpeg_encoder_threads,
                jpeg_fast_dct=jpeg_fast_dct,
                jpeg_tcp_queue_depth=jpeg_tcp_queue_depth,
            )
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
            _camera_stream_to_socket(
                sock, cap, jpeg_quality, overlay_timestamp, first_fr, jpeg_tcp_queue_depth=jpeg_tcp_queue_depth
            )
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
        _picamera2_stream_to_socket(
            sock,
            width,
            height,
            jpeg_quality,
            overlay_timestamp,
            fps,
            set_fps,
            picamera_use_jpeg_encoder=picamera_use_jpeg_encoder,
            jpeg_chroma_subsampling=jpeg_chroma_subsampling,
            jpeg_encoder_threads=jpeg_encoder_threads,
            jpeg_fast_dct=jpeg_fast_dct,
            jpeg_tcp_queue_depth=jpeg_tcp_queue_depth,
        )
    except BrokenPipeError:
        log.warning("TCP: соединение разорвано приёмником")
    except ImportError:
        log.error(
            "Установите: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
        )
    finally:
        sock.close()
        log.info("send: завершено")
