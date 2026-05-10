#!/usr/bin/env python3
"""
ПК: видео и управление Romeo — параллельно (разные потоки, два TCP-сокета).

Пока главный поток ждёт ввод команд или шлёт stress-тест, поток ``video-tcp``
непрерывно читает кадры с Pi — буфер видео не растёт и картинка не «замирает».

Запуск на удалённом ПК (скопируйте файл или весь репозиторий):

  python3 examples/pc_parallel_client.py --host 192.168.1.50

Окно предпросмотра (нужен OpenCV):

  pip install opencv-python-headless numpy
  python3 examples/pc_parallel_client.py --host IP_PI --window
  # Напряжение аккумулятора (делитель на канале АЦП по умолчанию, см. ROMEO_ADC_DEFAULT_CHANNEL в config) на кадре:
  python3 examples/pc_parallel_client.py --host IP_PI --window --battery-interval 0.5

Имитация «зажатой кнопки» (частые команды в отдельном потоке — видео всё равно в своём):

  python3 examples/pc_parallel_client.py --host IP_PI --stress --stress-interval 0.03

См. также docs/pc-remote-control.ru.md §6.
"""

from __future__ import annotations

import argparse
import json
import queue
import socket
import struct
import sys
import threading
import time


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    left = n
    while left > 0:
        part = sock.recv(left)
        if not part:
            raise EOFError("TCP закрыт")
        chunks.append(part)
        left -= len(part)
    return b"".join(chunks)


def video_receiver(
    host: str,
    port: int,
    stop: threading.Event,
    frame_queue: queue.Queue | None,
    quiet: bool,
) -> None:
    """Только читает видео-поток (протокол: 4 байта BE длина + JPEG)."""
    tag = "video"
    try:
        with socket.create_connection((host, port), timeout=15) as s:
            if not quiet:
                print(f"[{tag}] TCP {host}:{port}", flush=True)
            n_frames = 0
            n_bytes = 0
            t0 = time.monotonic()
            last_report = t0
            while not stop.is_set():
                try:
                    hdr = recv_exact(s, 4)
                except EOFError:
                    break
                (length,) = struct.unpack(">I", hdr)
                payload = recv_exact(s, length)
                n_frames += 1
                n_bytes += len(payload)
                if frame_queue is not None:
                    try:
                        frame_queue.put_nowait(payload)
                    except queue.Full:
                        try:
                            frame_queue.get_nowait()
                        except queue.Empty:
                            pass
                        try:
                            frame_queue.put_nowait(payload)
                        except queue.Full:
                            pass
                now = time.monotonic()
                if not quiet and now - last_report >= 2.0:
                    dt = now - t0
                    fps = n_frames / dt if dt > 0 else 0.0
                    mb_s = (n_bytes / max(dt, 1e-9)) / (1024 * 1024)
                    print(f"[{tag}] кадров={n_frames}  ~{fps:.1f} FPS  ~{mb_s:.2f} MiB/s", flush=True)
                    last_report = now
    except OSError as e:
        if not stop.is_set():
            print(f"[{tag}] ошибка: {e}", file=sys.stderr, flush=True)
    finally:
        stop.set()
        if not quiet:
            print(f"[{tag}] поток остановлен", flush=True)


def _read_json_line(sock: socket.socket, buf: bytearray, deadline: float) -> tuple[dict | None, bool]:
    while time.monotonic() < deadline:
        i = buf.find(b"\n")
        if i >= 0:
            line = bytes(buf[:i]).decode("utf-8", errors="replace")
            del buf[: i + 1]
            try:
                return json.loads(line), False
            except json.JSONDecodeError:
                return None, False
        try:
            sock.settimeout(min(0.2, max(0.01, deadline - time.monotonic())))
            chunk = sock.recv(4096)
            if not chunk:
                return None, True
            buf.extend(chunk)
        except TimeoutError:
            continue
    return None, False


def control_interactive(host: str, port: int, stop: threading.Event, quiet: bool) -> None:
    tag = "control"
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        print(f"[{tag}] нет соединения {host}:{port}: {e}", file=sys.stderr, flush=True)
        stop.set()
        return
    buf = bytearray()
    try:
        if not quiet:
            print(f"[{tag}] TCP {host}:{port} — вводите строки (JSON или MF), пусто — выход", flush=True)
        while not stop.is_set():
            try:
                line = input("control> ")
            except EOFError:
                break
            raw = line.strip()
            if not raw:
                break
            s.sendall((raw + "\n").encode("utf-8"))
            obj, closed = _read_json_line(s, buf, time.monotonic() + 5.0)
            if closed:
                break
            if obj is not None:
                print(f"[{tag}] {obj}", flush=True)
            elif not quiet:
                print(f"[{tag}] нет ответа за таймаут", flush=True)
    finally:
        stop.set()
        try:
            s.close()
        except OSError:
            pass
        if not quiet:
            print(f"[{tag}] выход", flush=True)


def stress_control_worker(
    host: str,
    port: int,
    stop: threading.Event,
    interval: float,
    seconds: float,
    quiet: bool,
) -> None:
    """Часто шлёт одну и ту же команду в отдельном потоке (проверка, что видео не блокируется)."""
    tag = "stress"
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        print(f"[{tag}] {e}", file=sys.stderr, flush=True)
        return
    buf = bytearray()
    fwd = '{"action":"drive","dir":"forward"}\n'.encode("utf-8")
    stp = '{"action":"drive","dir":"stop"}\n'.encode("utf-8")
    t_end = time.monotonic() + max(0.5, seconds)
    n = 0
    try:
        while not stop.is_set() and time.monotonic() < t_end:
            s.sendall(fwd)
            _read_json_line(s, buf, time.monotonic() + 1.0)
            n += 1
            time.sleep(max(0.005, interval))
        s.sendall(stp)
        _read_json_line(s, buf, time.monotonic() + 2.0)
    finally:
        try:
            s.close()
        except OSError:
            pass
        if not quiet:
            print(f"[{tag}] отправлено ~{n} команд за {seconds:.1f} с", flush=True)


def battery_sampler(
    host: str,
    port: int,
    interval: float,
    stop: threading.Event,
    quiet: bool,
    *,
    overlay_holder: dict | None,
    overlay_lock: threading.Lock | None,
) -> None:
    """Опрос JSON adc_read; либо кладёт battery_v в overlay_holder, либо печатает в stdout."""
    tag = "battery"
    buf = bytearray()
    cmd = b'{"action":"adc_read"}\n'
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        if not quiet:
            print(f"[{tag}] нет соединения {host}:{port}: {e}", file=sys.stderr, flush=True)
        return
    try:
        while not stop.is_set():
            try:
                s.sendall(cmd)
            except OSError:
                break
            obj, closed = _read_json_line(s, buf, time.monotonic() + 3.0)
            if closed:
                break
            if obj and obj.get("ok") and "battery_v" in obj:
                v = float(obj["battery_v"])
                if overlay_holder is not None and overlay_lock is not None:
                    with overlay_lock:
                        overlay_holder["battery_v"] = v
                elif not quiet:
                    print(f"[{tag}] {v:.2f} V (аккумулятор, АЦП по умолчанию на Pi)", flush=True)
            if stop.wait(max(0.05, interval)):
                break
    finally:
        try:
            s.close()
        except OSError:
            pass


def display_loop(
    frame_queue: queue.Queue,
    stop: threading.Event,
    overlay_holder: dict | None,
    overlay_lock: threading.Lock | None,
) -> None:
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except ImportError:
        print("[display] pip install opencv-python-headless numpy", file=sys.stderr, flush=True)
        return
    while not stop.is_set():
        try:
            jpeg = frame_queue.get(timeout=0.25)
        except queue.Empty:
            continue
        arr = np.frombuffer(jpeg, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame is None:
            continue
        if overlay_holder is not None and overlay_lock is not None:
            with overlay_lock:
                v = overlay_holder.get("battery_v")
            if v is not None:
                label = f"Battery: {v:.1f} V"
                cv2.putText(
                    frame,
                    label,
                    (10, 36),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.9,
                    (0, 0, 0),
                    4,
                    cv2.LINE_AA,
                )
                cv2.putText(
                    frame,
                    label,
                    (10, 36),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.9,
                    (255, 255, 255),
                    2,
                    cv2.LINE_AA,
                )
        cv2.imshow("Pi stream (parallel)", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            stop.set()
            break
    try:
        cv2.destroyAllWindows()
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="ПК: параллельно видео TCP + управление TCP")
    ap.add_argument("--host", required=True, help="IP Raspberry Pi")
    ap.add_argument("--video-port", type=int, default=5000)
    ap.add_argument("--control-port", type=int, default=5001)
    ap.add_argument("--no-control", action="store_true", help="только поток видео")
    ap.add_argument("--window", action="store_true", help="окно OpenCV (отдельный поток)")
    ap.add_argument("--stress", action="store_true", help="фоном слать drive forward с интервалом")
    ap.add_argument("--stress-interval", type=float, default=0.03, help="сек между командами")
    ap.add_argument("--stress-seconds", type=float, default=8.0, help="длительность stress")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--battery-interval",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Опрос АЦП на Pi (JSON adc_read, канал по умолчанию — A1); вывод battery_v: на кадр при --window, иначе в stdout",
    )
    args = ap.parse_args()

    stop = threading.Event()
    frame_queue: queue.Queue | None = queue.Queue(maxsize=2) if args.window else None
    overlay_holder: dict | None = None
    overlay_lock: threading.Lock | None = None
    if args.battery_interval > 0 and args.window:
        overlay_lock = threading.Lock()
        overlay_holder = {"battery_v": None}

    vt = threading.Thread(
        target=video_receiver,
        args=(args.host, args.video_port, stop, frame_queue, args.quiet),
        name="video-tcp",
        daemon=True,
    )
    vt.start()

    disp_t: threading.Thread | None = None
    if args.window and frame_queue is not None:
        disp_t = threading.Thread(
            target=display_loop,
            args=(frame_queue, stop, overlay_holder, overlay_lock),
            name="display",
            daemon=True,
        )
        disp_t.start()

    bat_t: threading.Thread | None = None
    if args.battery_interval > 0:
        bat_t = threading.Thread(
            target=battery_sampler,
            args=(
                args.host,
                args.control_port,
                args.battery_interval,
                stop,
                args.quiet,
            ),
            kwargs={
                "overlay_holder": overlay_holder,
                "overlay_lock": overlay_lock,
            },
            name="battery-tcp",
            daemon=True,
        )
        bat_t.start()

    stress_t: threading.Thread | None = None
    if args.stress:
        stress_t = threading.Thread(
            target=stress_control_worker,
            args=(
                args.host,
                args.control_port,
                stop,
                args.stress_interval,
                args.stress_seconds,
                args.quiet,
            ),
            name="stress-control",
            daemon=True,
        )
        stress_t.start()

    try:
        if args.no_control:
            if not args.quiet:
                print("Режим только видео. Ctrl+C — выход.", flush=True)
            while vt.is_alive() and not stop.is_set():
                time.sleep(0.25)
        elif args.stress:
            if not args.quiet:
                print(
                    f"Stress управления ~{args.stress_seconds:.0f} с (отдельный поток), видео — параллельно. Ctrl+C — выход.",
                    flush=True,
                )
            if stress_t is not None:
                stress_t.join(timeout=max(5.0, args.stress_seconds + 3.0))
            if not args.quiet:
                print("Stress завершён (роботу отправлен stop). Видео продолжается. Ctrl+C — выход.", flush=True)
            while vt.is_alive() and not stop.is_set():
                time.sleep(0.25)
        elif args.window and args.battery_interval > 0:
            if not args.quiet:
                print(
                    "Видео + напряжение аккумулятора на кадре (отдельное TCP к control). Ctrl+C — выход.",
                    flush=True,
                )
            while vt.is_alive() and not stop.is_set():
                time.sleep(0.25)
        else:
            control_interactive(args.host, args.control_port, stop, args.quiet)
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        vt.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
