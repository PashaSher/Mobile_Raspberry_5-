#!/usr/bin/env python3
"""
ПК: внешний player для H.264/TCP, MPEG-TS/UDP или RTP/UDP + управление Romeo по отдельному TCP.

По умолчанию скрипт запускает ``GStreamer`` для видео и держит отдельное соединение
с control-портом Pi. Видео больше не читается кастомным Python-приёмником:
основной поток на Pi теперь аппаратный H.264 по TCP, H.264 в MPEG-TS/UDP или RTP/UDP.

Примеры:

  python3 examples/pc_parallel_client.py --host 192.168.1.50
  python3 examples/pc_parallel_client.py --host 192.168.1.50 --video-transport udp
  python3 examples/pc_parallel_client.py --host 192.168.1.50 --player vlc
  python3 examples/pc_parallel_client.py --host 192.168.1.50 --video-transport rtp --player gstreamer
  python3 examples/pc_parallel_client.py --host 192.168.1.50 --player none --stress
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from shlex import join as shlex_join

_CAMERA_SHORTCUT_HELP = (
    "[control] camera shortcuts:\n"
    "  preset auto|day|cloudy|indoor|night|sport|hdr|mono\n"
    "  day | night | cloudy | indoor | sport | hdr | mono | auto\n"
    "  zoom+ | zoom- | zoom reset | zoom <factor>\n"
    "  cam status | cam presets\n"
    "Остальные строки уходят как raw JSON или Romeo-команды."
)


def _translate_control_shortcut(raw: str) -> tuple[str | None, str | None]:
    """Преобразует короткие команды ПК в JSON control-команды для Pi."""
    text = raw.strip()
    if not text:
        return None, None
    low = text.lower()
    if low in ("help", "cam-help"):
        return None, _CAMERA_SHORTCUT_HELP

    preset_aliases = {
        "auto": "auto",
        "day": "day",
        "cloudy": "cloudy",
        "indoor": "indoor",
        "night": "night",
        "sport": "sport",
        "hdr": "hdr",
        "mono": "mono",
        "bw": "mono",
    }
    if low in preset_aliases:
        return json.dumps({"action": "camera_preset", "preset": preset_aliases[low]}, ensure_ascii=False), None
    if low in ("zoom+", "zin", "zoom in"):
        return json.dumps({"action": "camera_zoom", "op": "in"}, ensure_ascii=False), None
    if low in ("zoom-", "zout", "zoom out"):
        return json.dumps({"action": "camera_zoom", "op": "out"}, ensure_ascii=False), None
    if low in ("zoom reset", "zoom 1", "zoom 1.0"):
        return json.dumps({"action": "camera_zoom", "op": "reset"}, ensure_ascii=False), None
    if low == "cam status":
        return json.dumps({"action": "camera_status"}, ensure_ascii=False), None
    if low == "cam presets":
        return json.dumps({"action": "camera_presets"}, ensure_ascii=False), None

    parts = low.split()
    if len(parts) == 2 and parts[0] == "preset" and parts[1] in preset_aliases:
        return json.dumps({"action": "camera_preset", "preset": preset_aliases[parts[1]]}, ensure_ascii=False), None
    if len(parts) == 2 and parts[0] == "zoom":
        try:
            factor = float(parts[1])
        except ValueError:
            pass
        else:
            return json.dumps({"action": "camera_zoom", "factor": factor}, ensure_ascii=False), None

    return text, None


def _video_sink_command() -> list[str]:
    if sys.platform.startswith("win"):
        return ["d3d11videosink", "sync=false"]
    return ["autovideosink", "sync=false"]


def _gstreamer_binary() -> str:
    env_path = os.environ.get("GST_LAUNCH_1_0") or os.environ.get("GST_LAUNCH")
    if env_path:
        return env_path
    resolved = shutil.which("gst-launch-1.0")
    if resolved:
        return resolved
    if sys.platform.startswith("win"):
        candidates = [
            Path.home() / "AppData/Local/Programs/gstreamer/1.0/msvc_x86_64/bin/gst-launch-1.0.exe",
            Path(r"C:\gstreamer\1.0\msvc_x86_64\bin\gst-launch-1.0.exe"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
    return "gst-launch-1.0"


def build_player_command(player: str, transport: str, host: str, port: int) -> list[str]:
    is_udp = transport == "udp"
    is_rtp = transport == "rtp"
    sink_cmd = _video_sink_command()
    if player == "ffplay":
        if is_rtp:
            raise ValueError("RTP operator mode рассчитан на GStreamer receiver (--player gstreamer)")
        cmd = [
            "ffplay",
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-framedrop",
            "-avioflags",
            "direct",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
        ]
        cmd.append(f"udp://@:{port}" if is_udp else f"tcp://{host}:{port}")
        return cmd
    if player == "vlc":
        if is_rtp:
            raise ValueError("RTP operator mode рассчитан на GStreamer receiver (--player gstreamer)")
        return ["vlc", f"udp://@:{port}"] if is_udp else ["vlc", f"tcp/h264://{host}:{port}"]
    if player == "gstreamer":
        gst = _gstreamer_binary()
        if is_rtp:
            return [
                gst,
                "-q",
                "udpsrc",
                f"port={port}",
                "buffer-size=262144",
                "caps=application/x-rtp,media=video,encoding-name=H264,payload=96,clock-rate=90000",
                "!",
                "queue",
                "max-size-time=0",
                "max-size-bytes=0",
                "max-size-buffers=4",
                "leaky=downstream",
                "!",
                "rtpjitterbuffer",
                "latency=10",
                "drop-on-latency=true",
                "faststart-min-packets=1",
                "!",
                "rtph264depay",
                "request-keyframe=true",
                "wait-for-keyframe=true",
                "!",
                "h264parse",
                "disable-passthrough=true",
                "!",
                "decodebin",
                "!",
                "queue",
                "max-size-time=0",
                "max-size-bytes=0",
                "max-size-buffers=1",
                "leaky=downstream",
                "!",
                "videoconvert",
                "!",
                *sink_cmd,
            ]
        if is_udp:
            if sys.platform.startswith("win"):
                return [
                    gst,
                    "-q",
                    "udpsrc",
                    f"port={port}",
                    "buffer-size=262144",
                    "!",
                    "tsdemux",
                    "!",
                    "h264parse",
                    "!",
                    "avdec_h264",
                    "!",
                    "videoconvert",
                    "!",
                    *sink_cmd,
                ]
            return [
                gst,
                "-q",
                "udpsrc",
                f"port={port}",
                "buffer-size=262144",
                "!",
                "tsdemux",
                "!",
                "h264parse",
                "!",
                "decodebin",
                "!",
                "videoconvert",
                "!",
                *sink_cmd,
            ]
        return [
            gst,
            "tcpclientsrc",
            f"host={host}",
            f"port={port}",
            "!",
            "h264parse",
            "!",
            "avdec_h264",
            "!",
            "videoconvert",
            "!",
            *sink_cmd,
        ]
    raise ValueError(f"неизвестный player: {player!r}")


def launch_player(player: str, transport: str, host: str, port: int, quiet: bool) -> subprocess.Popen | None:
    if player == "none":
        return None
    try:
        cmd = build_player_command(player, transport, host, port)
    except ValueError as exc:
        print(f"[video] {exc}", file=sys.stderr, flush=True)
        return None
    if not quiet:
        print(f"[video] запуск: {shlex_join(cmd)}", flush=True)
    try:
        return subprocess.Popen(cmd)
    except FileNotFoundError:
        print(f"[video] не найден player: {player}", file=sys.stderr, flush=True)
        return None


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
            print(_CAMERA_SHORTCUT_HELP, flush=True)
        while not stop.is_set():
            try:
                line = input("control> ")
            except EOFError:
                break
            raw = line.strip()
            if not raw:
                break
            outgoing, local_text = _translate_control_shortcut(raw)
            if local_text is not None:
                print(local_text, flush=True)
                continue
            if not outgoing:
                continue
            s.sendall((outgoing + "\n").encode("utf-8"))
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
) -> None:
    """Опрос JSON adc_read и вывод battery_v в stdout."""
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
                if not quiet:
                    print(f"[{tag}] {v:.2f} V (аккумулятор, АЦП по умолчанию на Pi)", flush=True)
            if stop.wait(max(0.05, interval)):
                break
    finally:
        try:
            s.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="ПК: внешний GStreamer/VLC/ffplay для H.264 TCP/UDP/RTP + управление TCP")
    ap.add_argument("--host", required=True, help="IP Raspberry Pi")
    ap.add_argument("--video-port", type=int, default=5000)
    ap.add_argument("--control-port", type=int, default=5001)
    ap.add_argument(
        "--video-transport",
        choices=["tcp", "udp", "rtp"],
        default="udp",
        help="Транспорт видеопотока с Pi: udp (mpeg-ts, рекомендуется), tcp или rtp.",
    )
    ap.add_argument(
        "--player",
        choices=["ffplay", "vlc", "gstreamer", "none"],
        default="gstreamer",
        help="Чем открывать видео с Pi (по умолчанию gstreamer; для RTP helper тоже использует gstreamer).",
    )
    ap.add_argument("--no-control", action="store_true", help="не открывать control-сессию, только видео")
    ap.add_argument("--stress", action="store_true", help="фоном слать drive forward с интервалом")
    ap.add_argument("--stress-interval", type=float, default=0.03, help="сек между командами")
    ap.add_argument("--stress-seconds", type=float, default=8.0, help="длительность stress")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--battery-interval",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Опрос АЦП на Pi (JSON adc_read, канал по умолчанию — A1); вывод battery_v в stdout",
    )
    args = ap.parse_args()

    player = args.player
    if args.video_transport == "rtp" and player == "ffplay":
        player = "gstreamer"
        if not args.quiet:
            print("[video] RTP mode: автоматически выбран GStreamer receiver", flush=True)

    stop = threading.Event()
    player_proc = launch_player(player, args.video_transport, args.host, args.video_port, args.quiet)
    if player != "none" and player_proc is None:
        return 1

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
                print("Режим только видео/player. Ctrl+C — выход.", flush=True)
            if player_proc is None:
                return 0
            while not stop.is_set():
                if player_proc is not None and player_proc.poll() is not None:
                    break
                time.sleep(0.25)
        elif args.stress:
            if not args.quiet:
                print(
                    f"Stress управления ~{args.stress_seconds:.0f} с (отдельный поток), видео идёт через внешний player. Ctrl+C — выход.",
                    flush=True,
                )
            if stress_t is not None:
                stress_t.join(timeout=max(5.0, args.stress_seconds + 3.0))
            if not args.quiet:
                print("Stress завершён (роботу отправлен stop). Видео продолжается. Ctrl+C — выход.", flush=True)
            if player_proc is None:
                return 0
            while not stop.is_set():
                if player_proc is not None and player_proc.poll() is not None:
                    break
                time.sleep(0.25)
        elif args.battery_interval > 0:
            if not args.quiet:
                print(
                    "Видео через внешний player + напряжение аккумулятора в stdout. Ctrl+C — выход.",
                    flush=True,
                )
            while not stop.is_set():
                if player_proc is not None and player_proc.poll() is not None:
                    break
                time.sleep(0.25)
        else:
            control_interactive(args.host, args.control_port, stop, args.quiet)
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        if player_proc is not None and player_proc.poll() is None:
            player_proc.terminate()
            try:
                player_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                player_proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
