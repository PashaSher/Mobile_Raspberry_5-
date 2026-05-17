"""?????? Raspberry Pi: RTSP/H.264, H.264 ?? TCP/UDP ? legacy MJPEG/JPEG ?? TCP, ????? listen + discovery."""

from __future__ import annotations

import errno
import gc
import io
import logging
import os
import queue
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Callable

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

# IMX708 / Camera Module 3: --awbgains red,blue (отключает AWB). Оба gain > ~1.1.
# Жёлтый: ниже red, выше blue; зелёный: выше red, ниже blue; яркость: --ev.
_IMX708_AWB_GAINS_NEUTRAL = "1.20,1.24"
_IMX708_AWB_GAINS_NATIVE = "1.26,1.18"
_IMX708_AWB_GAINS_DAY = "1.22,1.22"
_IMX708_AWB_GAINS_INDOOR = "1.24,1.20"
_IMX708_AWB_GAINS_COOL = "1.10,1.36"
_IMX708_EV_NEUTRAL = "-2.5"
_IMX708_NATIVE_EV = "-1"

# Встроенные режимы AWB libcamera (rpicam --awb). На IMX708 auto/tungsten часто синие.
_LIBCAMERA_AWB_MODES = frozenset({
    "auto",
    "incandescent",
    "tungsten",
    "fluorescent",
    "indoor",
    "daylight",
    "cloudy",
    "custom",
})

_CAMERA_PRESET_DEFS: dict[str, dict[str, object]] = {
    "native": {
        "description": (
            "IMX708 стрим: awbgains 1.26,1.18, ev -1, saturation 0.80 (сильно против зелёного)."
        ),
        "color_overrides": False,
        "args": [
            "--awbgains",
            _IMX708_AWB_GAINS_NATIVE,
            "--ev",
            _IMX708_NATIVE_EV,
            "--saturation",
            "0.80",
        ],
    },
    "native_auto": {
        "description": "Чистый libcamera: AWB auto, ev 0 (на IMX708 обычно сильно синий).",
        "color_overrides": False,
        "args": [],
    },
    "native_tungsten": {
        "description": "Только --awb tungsten (если gains слишком тёплые).",
        "color_overrides": False,
        "args": ["--awb", "tungsten"],
    },
    "auto": {
        "description": "IMX708: полная подстройка (1.14,1.32), ev -2.5.",
        "args": [
            "--awbgains",
            _IMX708_AWB_GAINS_NEUTRAL,
            "--ev",
            _IMX708_EV_NEUTRAL,
            "--metering",
            "centre",
            "--contrast",
            "0.94",
            "--saturation",
            "0.85",
            "--denoise",
            "auto",
            "--hdr",
            "off",
        ],
    },
    "day": {
        "description": "Дневной свет, слегка теплее нейтрали (1.16,1.28).",
        "args": [
            "--awbgains",
            _IMX708_AWB_GAINS_DAY,
            "--denoise",
            "auto",
            "--hdr",
            "off",
            "--contrast",
            "1.05",
            "--saturation",
            "1.05",
        ],
    },
    "cloudy": {
        "description": "Прохладный свет, убирает жёлтый (1.10,1.36).",
        "args": [
            "--awbgains",
            _IMX708_AWB_GAINS_COOL,
            "--denoise",
            "auto",
            "--hdr",
            "off",
            "--contrast",
            "1.04",
            "--saturation",
            "1.03",
        ],
    },
    "indoor": {
        "description": "Лампы в помещении, умеренно тёплый (1.18,1.26).",
        "args": ["--awbgains", _IMX708_AWB_GAINS_INDOOR, "--denoise", "auto", "--hdr", "off"],
    },
    "night": {
        "description": "Ночной/тёмный режим с усиленным шумоподавлением.",
        "args": [
            "--awb",
            "auto",
            "--metering",
            "average",
            "--denoise",
            "cdn_hq",
            "--shutter",
            "30000",
            "--gain",
            "10",
            "--contrast",
            "1.08",
            "--saturation",
            "0.95",
            "--hdr",
            "off",
        ],
    },
    "sport": {
        "description": "Быстрое движение, короче выдержка.",
        "args": ["--exposure", "sport", "--denoise", "cdn_fast", "--sharpness", "1.1", "--hdr", "off"],
    },
    "hdr": {
        "description": "HDR (для IMX708 sensor HDR там, где поддерживается).",
        "args": ["--awb", "auto", "--denoise", "auto", "--hdr", "sensor"],
    },
    "mono": {
        "description": "Чёрно-белый режим.",
        "args": ["--awb", "auto", "--denoise", "auto", "--saturation", "0.0", "--hdr", "off"],
    },
}

def _preset_color_overrides(preset: str) -> bool:
    """False = rpicam/libcamera по умолчанию (AWB auto, ev 0, saturation 1)."""
    item = _CAMERA_PRESET_DEFS.get(preset, {})
    return bool(item.get("color_overrides", True))


_CAMERA_PRESET_ALIASES = {
    "default": "native",
    "raw": "native",
    "libcamera": "native",
    "neutral": "auto",
    "imx708": "auto",
    "daylight": "day",
    "bw": "mono",
    "blackwhite": "mono",
    "black_and_white": "mono",
}


def _normalize_libcamera_awb_mode(name: object) -> str:
    mode = str(name or "").strip().lower()
    if mode not in _LIBCAMERA_AWB_MODES:
        allowed = ", ".join(sorted(_LIBCAMERA_AWB_MODES))
        raise ValueError(f"camera_awb_mode: неизвестный режим {name!r}; доступны: {allowed}")
    return mode


def _preset_rpicam_arg(args: list[str], flag: str) -> str | None:
    for i, item in enumerate(args):
        if item == flag and i + 1 < len(args):
            return str(args[i + 1])
    return None


def _awb_mode_from_preset_args(preset: str) -> str | None:
    args = _CAMERA_PRESET_DEFS.get(preset, {}).get("args", [])
    if not isinstance(args, list):
        return None
    return _preset_rpicam_arg(args, "--awb")


def _awbgains_from_preset_args(preset: str) -> str | None:
    args = _CAMERA_PRESET_DEFS.get(preset, {}).get("args", [])
    if not isinstance(args, list):
        return None
    return _preset_rpicam_arg(args, "--awbgains")


def _normalize_camera_preset_name(name: object) -> str:
    preset = str(name or "").strip().lower()
    preset = _CAMERA_PRESET_ALIASES.get(preset, preset)
    if preset not in _CAMERA_PRESET_DEFS:
        allowed = ", ".join(sorted(_CAMERA_PRESET_DEFS))
        raise ValueError(f"camera_preset: неизвестный preset {name!r}; доступны: {allowed}")
    return preset


def _parse_awb_gains(red: object, blue: object) -> str:
    try:
        r = float(red)
        b = float(blue)
    except (TypeError, ValueError) as e:
        raise ValueError("camera_awb: red и blue должны быть числами") from e
    if not (0.5 <= r <= 4.0 and 0.5 <= b <= 4.0):
        raise ValueError("camera_awb: red и blue вне диапазона 0.5..4.0")
    return f"{r:g},{b:g}"


def _strip_rpicam_option(args: list[str], flag: str) -> list[str]:
    out: list[str] = []
    skip = False
    for item in args:
        if skip:
            skip = False
            continue
        if item == flag:
            skip = True
            continue
        out.append(item)
    return out


def _strip_rpicam_awbgains(args: list[str]) -> list[str]:
    return _strip_rpicam_option(args, "--awbgains")


def _apply_env_rpicam_overrides(args: list[str]) -> list[str]:
    """Переопределение из env (удобно в launch.json без правки кода)."""
    out = list(args)
    gains = os.environ.get("CAMSTREAM_AWB_GAINS", "").strip()
    if gains:
        out = _strip_rpicam_awbgains(out)
        out = _strip_rpicam_option(out, "--awb")
        out.extend(("--awbgains", gains))
    ev = os.environ.get("CAMSTREAM_EV", "").strip()
    if ev:
        out = _strip_rpicam_option(out, "--ev")
        out.extend(("--ev", ev))
    sat = os.environ.get("CAMSTREAM_SATURATION", "").strip()
    if sat:
        out = _strip_rpicam_option(out, "--saturation")
        out.extend(("--saturation", sat))
    return out


def kill_stale_rpicam_processes() -> None:
    """Снять зависший rpicam-vid после Stop debug (иначе старые AWB gains)."""
    import subprocess
    import time

    for sig in ("-TERM", "-KILL"):
        for pattern in ("rpicam-vid", "libcamera-vid"):
            try:
                subprocess.run(
                    ["pkill", sig, "-f", pattern],
                    capture_output=True,
                    timeout=3,
                )
            except Exception:
                pass
        time.sleep(0.25)


def _zoom_factor_to_roi(zoom_factor: float) -> str | None:
    z = max(1.0, min(4.0, float(zoom_factor)))
    if z <= 1.0001:
        return None
    size = 1.0 / z
    x = (1.0 - size) / 2.0
    y = (1.0 - size) / 2.0
    return f"{x:.4f},{y:.4f},{size:.4f},{size:.4f}"


class _CameraControlState:
    """Текущее состояние rpicam/libcamera параметров, меняемых по control TCP."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._preset = "native"
        self._zoom_factor = 1.0
        self._awb_gains: str | None = None
        self._awb_mode: str | None = None
        self._ev: str | None = None
        self._generation = 0
        self._last_applied_rpicam_args: tuple[str, ...] | None = None

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def _effective_awb_mode(self) -> str:
        if self._awb_gains or _awbgains_from_preset_args(self._preset):
            return "manual"
        if self._awb_mode:
            return self._awb_mode
        from_preset = _awb_mode_from_preset_args(self._preset)
        if from_preset:
            return from_preset
        if _preset_color_overrides(self._preset):
            return "manual"
        return "auto"

    def _effective_ev(self) -> str | None:
        if self._ev is not None:
            return self._ev
        if _preset_color_overrides(self._preset):
            return _IMX708_EV_NEUTRAL
        preset = self._preset
        args = _CAMERA_PRESET_DEFS.get(preset, {}).get("args", [])
        if isinstance(args, list):
            return _preset_rpicam_arg(args, "--ev")
        return None

    def _color_fields_for_snapshot(self) -> dict[str, object]:
        preset = self._preset
        if self._awb_gains:
            awb_gains: object = self._awb_gains
        else:
            from_preset = _awbgains_from_preset_args(preset)
            if from_preset:
                awb_gains = from_preset
            elif _preset_color_overrides(preset):
                awb_gains = _IMX708_AWB_GAINS_NEUTRAL
            else:
                awb_gains = None
        ev_out: object = self._effective_ev()
        return {
            "awb_gains": awb_gains,
            "awb_mode": self._effective_awb_mode(),
            "ev": ev_out,
        }

    def snapshot(self) -> dict:
        with self._lock:
            roi = _zoom_factor_to_roi(self._zoom_factor)
            out = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": roi,
            }
            out.update(self._color_fields_for_snapshot())
            return out

    def mark_rpicam_applied(self, args: list[str]) -> None:
        with self._lock:
            self._last_applied_rpicam_args = tuple(args)

    def _rpicam_args_changed(self, args: list[str]) -> bool:
        with self._lock:
            return tuple(args) != self._last_applied_rpicam_args

    def _bump_generation_if_args_changed(self, args: list[str], mutated: bool) -> bool:
        """True если нужен перезапуск rpicam-vid (новые аргументы или явное изменение state)."""
        args_changed = self._rpicam_args_changed(args)
        if mutated or args_changed:
            with self._lock:
                self._generation += 1
        return mutated or args_changed

    def force_refresh(self) -> dict:
        args = self.build_rpicam_args()
        with self._lock:
            self._generation += 1
        snapshot = {
            "preset": self._preset,
            "zoom_factor": round(self._zoom_factor, 3),
            "roi": _zoom_factor_to_roi(self._zoom_factor),
        }
        snapshot.update(self._color_fields_for_snapshot())
        return {
            "ok": True,
            "camera_action": "camera_refresh",
            "changed": True,
            "camera": snapshot,
            "rpicam_args": args,
        }

    def build_rpicam_args(self) -> list[str]:
        with self._lock:
            preset = self._preset
            zoom_factor = self._zoom_factor
            awb_gains = self._awb_gains
            awb_mode = self._awb_mode
            ev_override = self._ev
            color_preset = _preset_color_overrides(preset)
        preset_args = list(_CAMERA_PRESET_DEFS[preset]["args"])  # type: ignore[index]
        if awb_gains:
            preset_args = _strip_rpicam_awbgains(preset_args)
            preset_args = _strip_rpicam_option(preset_args, "--awb")
            preset_args.extend(("--awbgains", awb_gains))
        elif awb_mode:
            preset_args = _strip_rpicam_awbgains(preset_args)
            preset_args = _strip_rpicam_option(preset_args, "--awb")
            preset_args.extend(("--awb", awb_mode))
        preset_args = _strip_rpicam_option(preset_args, "--ev")
        if ev_override is not None:
            preset_args.extend(("--ev", ev_override))
        elif color_preset:
            preset_args.extend(("--ev", _IMX708_EV_NEUTRAL))
        else:
            ev_from_preset = _preset_rpicam_arg(
                list(_CAMERA_PRESET_DEFS[preset]["args"]),  # type: ignore[index]
                "--ev",
            )
            if ev_from_preset is not None:
                preset_args.extend(("--ev", ev_from_preset))
        roi = _zoom_factor_to_roi(zoom_factor)
        if roi:
            preset_args.extend(("--roi", roi))
        return _apply_env_rpicam_overrides(preset_args)

    def set_awb_gains(self, red: object, blue: object) -> dict:
        gains = _parse_awb_gains(red, blue)
        with self._lock:
            mutated = gains != self._awb_gains
            if mutated:
                self._awb_gains = gains
                self._awb_mode = None
        args = self.build_rpicam_args()
        changed = self._bump_generation_if_args_changed(args, mutated)
        with self._lock:
            snapshot = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": _zoom_factor_to_roi(self._zoom_factor),
            }
            snapshot.update(self._color_fields_for_snapshot())
        return {
            "ok": True,
            "camera_action": "camera_awb",
            "changed": changed,
            "camera": snapshot,
            "rpicam_args": args,
        }

    def set_awb_mode(self, mode: object) -> dict:
        awb_mode = _normalize_libcamera_awb_mode(mode)
        with self._lock:
            mutated = awb_mode != self._effective_awb_mode()
            if mutated:
                self._awb_mode = awb_mode
                self._awb_gains = None
        args = self.build_rpicam_args()
        changed = self._bump_generation_if_args_changed(args, mutated)
        with self._lock:
            snapshot = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": _zoom_factor_to_roi(self._zoom_factor),
            }
            snapshot.update(self._color_fields_for_snapshot())
        return {
            "ok": True,
            "camera_action": "camera_awb_mode",
            "changed": changed,
            "camera": snapshot,
            "rpicam_args": args,
            "available_awb_modes": sorted(_LIBCAMERA_AWB_MODES),
        }

    def set_ev(self, ev: object) -> dict:
        try:
            ev_val = float(ev)
        except (TypeError, ValueError) as e:
            raise ValueError("camera_ev: ev должен быть числом (например -2.0)") from e
        if not (-4.0 <= ev_val <= 4.0):
            raise ValueError("camera_ev: ev вне диапазона -4.0..4.0")
        ev_str = f"{ev_val:g}"
        with self._lock:
            if self._ev is not None:
                prev = self._ev
            elif _preset_color_overrides(self._preset):
                prev = _IMX708_EV_NEUTRAL
            else:
                prev = "0"
            mutated = ev_str != prev
            if mutated:
                self._ev = ev_str
        args = self.build_rpicam_args()
        changed = self._bump_generation_if_args_changed(args, mutated)
        with self._lock:
            snapshot = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": _zoom_factor_to_roi(self._zoom_factor),
            }
            snapshot.update(self._color_fields_for_snapshot())
        return {
            "ok": True,
            "camera_action": "camera_ev",
            "changed": changed,
            "camera": snapshot,
            "rpicam_args": args,
        }

    def set_preset(self, preset_name: object) -> dict:
        preset = _normalize_camera_preset_name(preset_name)
        with self._lock:
            mutated = preset != self._preset
            if mutated:
                self._preset = preset
                if not _preset_color_overrides(preset):
                    self._awb_gains = None
                    self._awb_mode = None
                    self._ev = None
        args = self.build_rpicam_args()
        changed = self._bump_generation_if_args_changed(args, mutated)
        with self._lock:
            snapshot = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": _zoom_factor_to_roi(self._zoom_factor),
            }
            snapshot.update(self._color_fields_for_snapshot())
        return {
            "ok": True,
            "camera_action": "camera_preset",
            "changed": changed,
            "camera": snapshot,
            "rpicam_args": args,
            "available_presets": sorted(_CAMERA_PRESET_DEFS),
        }

    def set_zoom_factor(self, zoom_factor: float) -> dict:
        try:
            target = float(zoom_factor)
        except (TypeError, ValueError) as e:
            raise ValueError("camera_zoom: factor должен быть числом 1.0..4.0") from e
        target = max(1.0, min(4.0, target))
        with self._lock:
            changed = abs(target - self._zoom_factor) >= 1e-4
            if changed:
                self._zoom_factor = target
                self._generation += 1
            snapshot = {
                "preset": self._preset,
                "zoom_factor": round(self._zoom_factor, 3),
                "roi": _zoom_factor_to_roi(self._zoom_factor),
            }
        return {
            "ok": True,
            "camera_action": "camera_zoom",
            "changed": changed,
            "camera": snapshot,
        }

    def step_zoom(self, direction: str, step: float = 1.25) -> dict:
        d = str(direction or "").strip().lower()
        with self._lock:
            current = self._zoom_factor
        if d == "in":
            return self.set_zoom_factor(current * max(1.01, float(step)))
        if d == "out":
            return self.set_zoom_factor(current / max(1.01, float(step)))
        if d == "reset":
            return self.set_zoom_factor(1.0)
        raise ValueError("camera_zoom: op должен быть in|out|reset")

    def presets_payload(self) -> dict:
        presets = []
        for name in sorted(_CAMERA_PRESET_DEFS):
            item = _CAMERA_PRESET_DEFS[name]
            presets.append({"name": name, "description": item["description"]})
        return {"ok": True, "camera_action": "camera_presets", "presets": presets}

    def status_payload(self) -> dict:
        args = self.build_rpicam_args()
        return {
            "ok": True,
            "camera_action": "camera_status",
            "camera": self.snapshot(),
            "rpicam_args": args,
            "rpicam_applied": list(self._last_applied_rpicam_args or ()),
            "available_presets": sorted(_CAMERA_PRESET_DEFS),
        }


def _make_camera_control_handler(state: _CameraControlState) -> Callable[[dict], dict | None]:
    def _handle(obj: dict) -> dict | None:
        if not isinstance(obj, dict):
            raise ValueError("camera-control: ожидался JSON-объект")
        act = str(obj.get("action", "")).strip().lower()
        if act in ("camera_status", "camera"):
            return state.status_payload()
        if act in ("camera_refresh", "camera_apply"):
            return state.force_refresh()
        if act in ("camera_presets", "camera_list_presets"):
            return state.presets_payload()
        if act in ("camera_preset", "camera_mode"):
            preset = obj.get("preset", obj.get("mode"))
            if preset is None:
                raise ValueError("camera_preset: нужно поле preset")
            return state.set_preset(preset)
        if act == "camera_zoom":
            if "factor" in obj and obj.get("factor") is not None:
                return state.set_zoom_factor(obj.get("factor"))
            op = obj.get("op", obj.get("dir", ""))
            step = obj.get("step", 1.25)
            if op is None:
                raise ValueError("camera_zoom: укажите op=in|out|reset или factor")
            return state.step_zoom(str(op), float(step))
        if act == "camera_awb":
            red = obj.get("red", obj.get("r"))
            blue = obj.get("blue", obj.get("b"))
            if red is None or blue is None:
                raw = obj.get("awb_gains", obj.get("gains"))
                if isinstance(raw, str) and "," in raw:
                    red_s, blue_s = raw.split(",", 1)
                    red, blue = red_s.strip(), blue_s.strip()
                else:
                    raise ValueError('camera_awb: укажите red/blue или awb_gains "1.18,1.06"')
            return state.set_awb_gains(red, blue)
        if act == "camera_awb_mode":
            mode = obj.get("mode", obj.get("awb", obj.get("awb_mode")))
            if mode is None:
                raise ValueError(
                    'camera_awb_mode: укажите mode (tungsten, daylight, fluorescent, auto, …)'
                )
            return state.set_awb_mode(mode)
        if act == "camera_ev":
            if "ev" not in obj:
                raise ValueError('camera_ev: укажите поле ev (например -2.0)')
            return state.set_ev(obj.get("ev"))
        return None

    return _handle


def _terminate_process(proc: subprocess.Popen, label: str) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        log.warning("%s: процесс не завершился по terminate(), принудительный kill", label)
        proc.kill()


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


def _h264_stream_tool_path() -> str | None:
    """Предпочитаем rpicam-vid (Bookworm), fallback — libcamera-vid."""
    for name in ("rpicam-vid", "libcamera-vid"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _default_video_mode(listen: bool, overlay_timestamp: bool, host: str = "auto") -> str:
    """
    Авто-режим:
    - listen + без overlay + есть системный libcamera/rpicam-инструмент -> H.264/TCP;
    - push + явный --host + без overlay + есть системный libcamera/rpicam-инструмент -> H.264 в MPEG-TS/UDP;
    - иначе legacy JPEG/TCP (совместимо со старым кастомным клиентом).
    """
    host_value = str(host or "auto").strip().lower()
    if not overlay_timestamp and _h264_stream_tool_path():
        if listen:
            return "h264_tcp"
        if host_value not in ("", "auto", "discover"):
            return "udp_h264"
    return "jpeg_tcp"


def _check_listen_bind_available(tcp_port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("0.0.0.0", tcp_port))
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
    finally:
        probe.close()


def _build_h264_tcp_listen_command(
    tool_path: str,
    tcp_port: int,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
    camera_extra_args: list[str] | None = None,
) -> list[str]:
    w = max(64, int(width))
    h = max(64, int(height))
    fr = max(1.0, float(fps))
    bitrate = max(1_000_000, int(video_bitrate))
    cmd = [
        tool_path,
        "-t",
        "0",
        "-n",
        "--flush",
        "--codec",
        "h264",
        "--inline",
        "--width",
        str(w),
        "--height",
        str(h),
        "--framerate",
        f"{fr:g}",
        "--bitrate",
        str(bitrate),
    ]
    if video_intra > 0:
        cmd.extend(("--intra", str(max(1, int(video_intra)))))
    if video_profile:
        cmd.extend(("--profile", str(video_profile)))
    if video_level:
        cmd.extend(("--level", str(video_level)))
    if camera_extra_args:
        cmd.extend(camera_extra_args)
    cmd.extend(("--listen", "-o", f"tcp://0.0.0.0:{tcp_port}"))
    return cmd


def _build_h264_udp_command(
    tool_path: str,
    host: str,
    udp_port: int,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
    camera_extra_args: list[str] | None = None,
) -> list[str]:
    w = max(64, int(width))
    h = max(64, int(height))
    fr = max(1.0, float(fps))
    bitrate = max(1_000_000, int(video_bitrate))
    cmd = [
        tool_path,
        "-t",
        "0",
        "-n",
        "--flush",
        "--codec",
        "libav",
        "--libav-format",
        "mpegts",
        "--libav-video-codec",
        "h264_v4l2m2m",
        "--low-latency",
        "--width",
        str(w),
        "--height",
        str(h),
        "--framerate",
        f"{fr:g}",
        "--bitrate",
        str(bitrate),
    ]
    if video_intra > 0:
        cmd.extend(("--intra", str(max(1, int(video_intra)))))
    if video_profile:
        cmd.extend(("--profile", str(video_profile)))
    if video_level:
        cmd.extend(("--level", str(video_level)))
    if camera_extra_args:
        cmd.extend(camera_extra_args)
    cmd.extend(("-o", f"udp://{host}:{udp_port}?pkt_size=1316"))
    return cmd


def _build_h264_stdout_command(
    tool_path: str,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
    camera_extra_args: list[str] | None = None,
) -> list[str]:
    w = max(64, int(width))
    h = max(64, int(height))
    fr = max(1.0, float(fps))
    bitrate = max(1_000_000, int(video_bitrate))
    cmd = [
        tool_path,
        "-t",
        "0",
        "-n",
        "--flush",
        "--codec",
        "libav",
        "--libav-format",
        "h264",
        "--libav-video-codec",
        "h264_v4l2m2m",
        "--low-latency",
        "--inline",
        "--width",
        str(w),
        "--height",
        str(h),
        "--framerate",
        f"{fr:g}",
        "--bitrate",
        str(bitrate),
        "-o",
        "-",
    ]
    if video_intra > 0:
        cmd.extend(("--intra", str(max(1, int(video_intra)))))
    if video_profile:
        cmd.extend(("--profile", str(video_profile)))
    if video_level:
        cmd.extend(("--level", str(video_level)))
    if camera_extra_args:
        cmd.extend(camera_extra_args)
    return cmd


def _build_gstreamer_rtp_send_command(host: str, udp_port: int) -> list[str]:
    return [
        "gst-launch-1.0",
        "-q",
        "fdsrc",
        "fd=0",
        "do-timestamp=true",
        "is-live=true",
        "blocksize=65536",
        "!",
        "queue",
        "max-size-time=0",
        "max-size-bytes=0",
        "max-size-buffers=2",
        "leaky=downstream",
        "!",
        "h264parse",
        "disable-passthrough=true",
        "!",
        "rtph264pay",
        "pt=96",
        "config-interval=1",
        "aggregate-mode=none",
        "mtu=1200",
        "!",
        "queue",
        "max-size-time=0",
        "max-size-bytes=0",
        "max-size-buffers=4",
        "leaky=downstream",
        "!",
        "udpsink",
        f"host={host}",
        f"port={int(udp_port)}",
        "buffer-size=262144",
        "sync=false",
        "async=false",
    ]




def _normalize_rtsp_mount_path(rtsp_path: str | None) -> str:
    path = str(rtsp_path or "camera").strip().strip('"').strip("'")
    if not path:
        path = "camera"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _import_gst_rtsp_modules():
    try:
        import gi  # type: ignore
    except ImportError:
        log.error(
            "????? python3-gi/python3-gst-1.0 ? RTSP bindings: sudo apt install -y "
            "python3-gi python3-gst-1.0 gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0 gstreamer1.0-rtsp"
        )
        return None
    try:
        gi.require_version("Gst", "1.0")
        gi.require_version("GstRtspServer", "1.0")
        from gi.repository import GLib, Gst, GstRtspServer  # type: ignore
    except (ValueError, ImportError) as exc:
        log.error(
            "?? ??????? GStreamer RTSP Python bindings (%s). ??????????: sudo apt install -y "
            "python3-gi python3-gst-1.0 gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0 gstreamer1.0-rtsp",
            exc,
        )
        return None
    Gst.init(None)
    return GLib, Gst, GstRtspServer


def _build_gstreamer_rtsp_relay_launch(local_udp_port: int) -> str:
    caps = "application/x-rtp,media=video,encoding-name=H264,payload=96,clock-rate=90000"
    return (
        f'( udpsrc address=127.0.0.1 port={int(local_udp_port)} buffer-size=262144 caps="{caps}" '
        '! queue max-size-time=0 max-size-bytes=0 max-size-buffers=4 leaky=downstream '
        '! rtph264depay request-keyframe=true wait-for-keyframe=true '
        '! h264parse disable-passthrough=true '
        '! rtph264pay name=pay0 pt=96 config-interval=1 aggregate-mode=none mtu=1200 )'
    )


def _run_h264_rtsp_server(
    rtsp_port: int,
    rtsp_path: str,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
) -> None:
    tool_path = _h264_stream_tool_path()
    gst_path = shutil.which("gst-launch-1.0")
    rtsp_mods = _import_gst_rtsp_modules()
    if not tool_path:
        log.error(
            "?? ?????? rpicam-vid/libcamera-vid. ?????????? ????? ?????? Raspberry Pi "
            "??? ????????????? ? legacy ?????: --video-mode jpeg_tcp."
        )
        sys.exit(1)
    if not gst_path:
        log.error("?? ?????? gst-launch-1.0. ?????????? GStreamer tools: sudo apt install -y gstreamer1.0-tools")
        sys.exit(1)
    if rtsp_mods is None:
        sys.exit(1)
    GLib, _Gst, GstRtspServer = rtsp_mods
    mount_path = _normalize_rtsp_mount_path(rtsp_path)
    relay_udp_port = max(1024, int(rtsp_port) + 200)
    src_cmd = _build_h264_stdout_command(
        tool_path,
        width,
        height,
        fps,
        video_bitrate,
        video_intra,
        video_profile,
        video_level,
    )
    sink_cmd = _build_gstreamer_rtp_send_command("127.0.0.1", relay_udp_port)
    if int(video_bitrate) > 12_000_000:
        log.warning(
            "RTSP H.264: bitrate=%d bps ????? ???? ??????? ??????? ??? Wi?Fi; "
            "???? ?????? ???/?????, ?????????? --stream-preset realtime ??? 4-8 ????/?.",
            int(video_bitrate),
        )
    if int(width) * int(height) > 1280 * 720:
        log.warning(
            "RTSP H.264: ?????????? %dx%d ????? ???? ??????? ??? ?????? ?????????? ?? Wi?Fi; "
            "??? ??????????? ???????? ?????? ????? 960x540 ??? 1280x720.",
            int(width),
            int(height),
        )
    log.info(
        "H.264/RTSP: %s, rtsp://<pi-ip>:%d%s, %dx%d @%.2f fps, bitrate=%d bps, intra=%s, profile=%s%s",
        os.path.basename(tool_path),
        int(rtsp_port),
        mount_path,
        max(64, int(width)),
        max(64, int(height)),
        max(1.0, float(fps)),
        max(1_000_000, int(video_bitrate)),
        max(1, int(video_intra)) if int(video_intra) > 0 else "auto",
        video_profile or "auto",
        f", level={video_level}" if video_level else "",
    )
    log.info(
        "H.264/RTSP: ffplay -fflags nobuffer -flags low_delay -framedrop -rtsp_transport tcp rtsp://<pi-ip>:%d%s",
        int(rtsp_port),
        mount_path,
    )

    server = GstRtspServer.RTSPServer()
    server.set_service(str(int(rtsp_port)))
    mounts = server.get_mount_points()
    factory = GstRtspServer.RTSPMediaFactory()
    factory.set_shared(True)
    factory.set_launch(_build_gstreamer_rtsp_relay_launch(relay_udp_port))
    mounts.add_factory(mount_path, factory)
    if server.attach(None) == 0:
        log.error("H.264/RTSP: ?? ??????? ????????? RTSP server ?? ????? %s", rtsp_port)
        sys.exit(1)

    src_proc = None
    gst_proc = None
    loop = GLib.MainLoop()

    def _poll_children() -> bool:
        src_rc = None if src_proc is None else src_proc.poll()
        gst_rc = None if gst_proc is None else gst_proc.poll()
        if src_rc is None and gst_rc is None:
            return True
        log.error("H.264/RTSP: ???????? ??????????? ? ?????? src=%s gst=%s", src_rc, gst_rc)
        loop.quit()
        return False

    try:
        src_proc = subprocess.Popen(src_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert src_proc.stdout is not None
        gst_proc = subprocess.Popen(
            sink_cmd,
            stdin=src_proc.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        src_proc.stdout.close()
        GLib.timeout_add(500, _poll_children)
        loop.run()
    except KeyboardInterrupt:
        log.info("H.264/RTSP: ????????? ?? Ctrl+C")
    finally:
        for proc in (gst_proc, src_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
        for proc in (gst_proc, src_proc):
            if proc is not None and proc.poll() is None:
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
def _run_h264_tcp_listen(
    tcp_port: int,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
    camera_controls: _CameraControlState | None = None,
) -> None:
    tool_path = _h264_stream_tool_path()
    if not tool_path:
        log.error(
            "Не найден rpicam-vid/libcamera-vid. Установите пакет камеры Raspberry Pi "
            "или переключитесь в legacy режим: --video-mode jpeg_tcp."
        )
        sys.exit(1)
    _check_listen_bind_available(tcp_port)
    tool_name = os.path.basename(tool_path)
    log.info(
        "H.264/TCP: %s, %dx%d @%.2f fps, bitrate=%d bps, intra=%s, profile=%s%s",
        tool_name,
        max(64, int(width)),
        max(64, int(height)),
        max(1.0, float(fps)),
        max(1_000_000, int(video_bitrate)),
        max(1, int(video_intra)) if int(video_intra) > 0 else "auto",
        video_profile or "auto",
        f", level={video_level}" if video_level else "",
    )
    log.info("H.264/TCP: ffplay tcp://<ip>:%s", tcp_port)
    log.info("H.264/TCP: VLC tcp/h264://<ip>:%s", tcp_port)
    try:
        while True:
            camera_args = camera_controls.build_rpicam_args() if camera_controls is not None else None
            if camera_controls is not None:
                snapshot = camera_controls.snapshot()
                log.info(
                    "H.264/TCP: camera preset=%s, zoom=%.2fx%s",
                    snapshot["preset"],
                    float(snapshot["zoom_factor"]),
                    f", roi={snapshot['roi']}" if snapshot["roi"] else "",
                )
            cmd = _build_h264_tcp_listen_command(
                tool_path,
                tcp_port,
                width,
                height,
                fps,
                video_bitrate,
                video_intra,
                video_profile,
                video_level,
                camera_extra_args=camera_args,
            )
            proc = subprocess.Popen(cmd)
            launch_generation = camera_controls.generation() if camera_controls is not None else 0
            restart_for_camera_change = False
            while True:
                rc = proc.poll()
                if rc is not None:
                    break
                if camera_controls is not None and camera_controls.generation() != launch_generation:
                    restart_for_camera_change = True
                    log.info("H.264/TCP: настройки камеры изменены, перезапуск rpicam/libcamera ...")
                    _terminate_process(proc, "H.264/TCP")
                    break
                time.sleep(0.2)
            if restart_for_camera_change:
                continue
            if rc == 0:
                log.info("H.264/TCP: сессия завершена, снова ожидание клиента на TCP %s ...", tcp_port)
                continue
            if rc in (130, 143):
                log.info("H.264/TCP: остановка (код=%s)", rc)
                return
            log.warning("H.264/TCP: %s завершился с кодом %s, повтор через 1 с ...", tool_name, rc)
            time.sleep(1.0)
    except KeyboardInterrupt:
        log.info("H.264/TCP: остановка по Ctrl+C")


def _run_h264_udp_push(
    host: str,
    udp_port: int,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
    camera_controls: _CameraControlState | None = None,
) -> None:
    tool_path = _h264_stream_tool_path()
    if not tool_path:
        log.error(
            "Не найден rpicam-vid/libcamera-vid. Установите пакет камеры Raspberry Pi "
            "или переключитесь в legacy режим: --video-mode jpeg_tcp."
        )
        sys.exit(1)
    tool_name = os.path.basename(tool_path)
    if int(video_bitrate) > 12_000_000:
        log.warning(
            "UDP low-latency: bitrate=%d bps может быть слишком высоким для Wi‑Fi; "
            "если будут лаги/фризы, попробуйте --stream-preset realtime или 4-8 Мбит/с.",
            int(video_bitrate),
        )
    if int(width) * int(height) > 1280 * 720:
        log.warning(
            "UDP low-latency: разрешение %dx%d может быть тяжёлым для живого управления по Wi‑Fi; "
            "для минимальной задержки обычно лучше 960x540 или 1280x720.",
            int(width),
            int(height),
        )
    log.info(
        "H.264/UDP(MPEG-TS): %s -> %s:%d, %dx%d @%.2f fps, bitrate=%d bps, intra=%s, profile=%s%s",
        tool_name,
        host,
        int(udp_port),
        max(64, int(width)),
        max(64, int(height)),
        max(1.0, float(fps)),
        max(1_000_000, int(video_bitrate)),
        max(1, int(video_intra)) if int(video_intra) > 0 else "auto",
        video_profile or "auto",
        f", level={video_level}" if video_level else "",
    )
    log.info(
        "H.264/UDP(MPEG-TS): GStreamer gst-launch-1.0 udpsrc port=%d buffer-size=262144 "
        "! tsdemux ! h264parse ! decodebin ! videoconvert ! autovideosink sync=false",
        int(udp_port),
    )
    try:
        while True:
            camera_args = camera_controls.build_rpicam_args() if camera_controls is not None else None
            if camera_controls is not None:
                snapshot = camera_controls.snapshot()
                log.info(
                    "H.264/UDP(MPEG-TS): camera preset=%s, zoom=%.2fx%s",
                    snapshot["preset"],
                    float(snapshot["zoom_factor"]),
                    f", roi={snapshot['roi']}" if snapshot["roi"] else "",
                )
            cmd = _build_h264_udp_command(
                tool_path,
                host,
                udp_port,
                width,
                height,
                fps,
                video_bitrate,
                video_intra,
                video_profile,
                video_level,
                camera_extra_args=camera_args,
            )
            proc = subprocess.Popen(cmd)
            launch_generation = camera_controls.generation() if camera_controls is not None else 0
            restart_for_camera_change = False
            while True:
                rc = proc.poll()
                if rc is not None:
                    break
                if camera_controls is not None and camera_controls.generation() != launch_generation:
                    restart_for_camera_change = True
                    log.info("H.264/UDP(MPEG-TS): настройки камеры изменены, перезапуск rpicam/libcamera ...")
                    _terminate_process(proc, "H.264/UDP(MPEG-TS)")
                    break
                time.sleep(0.2)
            if restart_for_camera_change:
                continue
            if rc in (0, 130, 143):
                log.info("H.264/UDP(MPEG-TS): остановка (код=%s)", rc)
                return
            log.warning(
                "H.264/UDP(MPEG-TS): %s завершился с кодом %s. "
                "Часто это значит, что ПК ещё не подключился к точке доступа "
                "или у клиента уже сменился IP %s. Повтор через 2 с ...",
                tool_name,
                rc,
                host,
            )
            time.sleep(2.0)
    except KeyboardInterrupt:
        log.info("H.264/UDP(MPEG-TS): остановка по Ctrl+C")


def _run_h264_rtp_push(
    host: str,
    udp_port: int,
    width: int,
    height: int,
    fps: float,
    video_bitrate: int,
    video_intra: int,
    video_profile: str | None,
    video_level: str | None,
) -> None:
    tool_path = _h264_stream_tool_path()
    gst_path = shutil.which("gst-launch-1.0")
    if not tool_path:
        log.error(
            "Не найден rpicam-vid/libcamera-vid. Установите пакет камеры Raspberry Pi "
            "или переключитесь в legacy режим: --video-mode jpeg_tcp."
        )
        sys.exit(1)
    if not gst_path:
        log.error("Не найден gst-launch-1.0. Установите GStreamer tools: sudo apt install -y gstreamer1.0-tools")
        sys.exit(1)
    src_cmd = _build_h264_stdout_command(
        tool_path,
        width,
        height,
        fps,
        video_bitrate,
        video_intra,
        video_profile,
        video_level,
    )
    sink_cmd = _build_gstreamer_rtp_send_command(host, udp_port)
    if int(video_bitrate) > 12_000_000:
        log.warning(
            "RTP low-latency: bitrate=%d bps может быть слишком высоким для Wi‑Fi; "
            "если видите лаг/фризы, начните с --stream-preset realtime или 4-8 Мбит/с.",
            int(video_bitrate),
        )
    if int(width) * int(height) > 1280 * 720:
        log.warning(
            "RTP low-latency: разрешение %dx%d может быть тяжёлым для живого управления по Wi‑Fi; "
            "для минимальной задержки обычно лучше 960x540 или 1280x720.",
            int(width),
            int(height),
        )
    log.info(
        "H.264/RTP: %s -> %s:%d, %dx%d @%.2f fps, bitrate=%d bps, intra=%s, profile=%s%s",
        os.path.basename(tool_path),
        host,
        int(udp_port),
        max(64, int(width)),
        max(64, int(height)),
        max(1.0, float(fps)),
        max(1_000_000, int(video_bitrate)),
        max(1, int(video_intra)) if int(video_intra) > 0 else "auto",
        video_profile or "auto",
        f", level={video_level}" if video_level else "",
    )
    log.info(
        "H.264/RTP: gst-launch-1.0 udpsrc port=%d "
        "caps=application/x-rtp,media=video,encoding-name=H264,payload=96,clock-rate=90000 "
        "! queue max-size-time=0 max-size-bytes=0 max-size-buffers=4 leaky=downstream "
        "! rtpjitterbuffer latency=10 drop-on-latency=true faststart-min-packets=1 "
        "! rtph264depay request-keyframe=true wait-for-keyframe=true "
        "! h264parse disable-passthrough=true ! decodebin ! queue max-size-time=0 max-size-bytes=0 max-size-buffers=1 leaky=downstream "
        "! videoconvert ! autovideosink sync=false",
        int(udp_port),
    )
    src_proc = None
    gst_proc = None
    try:
        src_proc = subprocess.Popen(src_cmd, stdout=subprocess.PIPE)
        assert src_proc.stdout is not None
        gst_proc = subprocess.Popen(sink_cmd, stdin=src_proc.stdout)
        src_proc.stdout.close()
        gst_rc = gst_proc.wait()
        src_rc = src_proc.wait()
        if gst_rc in (0, 130, 143) and src_rc in (0, 130, 141, 143):
            log.info("H.264/RTP: остановка (src=%s, gst=%s)", src_rc, gst_rc)
            return
        log.error("H.264/RTP: процессы завершились с кодами src=%s gst=%s", src_rc, gst_rc)
        sys.exit(gst_rc if isinstance(gst_rc, int) and gst_rc != 0 else 1)
    except KeyboardInterrupt:
        log.info("H.264/RTP: остановка по Ctrl+C")
    finally:
        for proc in (gst_proc, src_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
        for proc in (gst_proc, src_proc):
            if proc is not None and proc.poll() is None:
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()


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
    """Резкость/шум — без ручной коррекции цвета (AWB/EV/saturation — libcamera)."""
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

    # BGR888 + simplejpeg colorspace "RGB" — корректные цвета на Pi 5 (libcamera 0.7+).
    _picam_format = "BGR888"
    cfg = picam2.create_video_configuration(
        main={"size": (w, h), "format": _picam_format},
        buffer_count=6,
        controls=fps_ctl or {},
    )
    try:
        picam2.configure(cfg)
    except Exception as e:
        log.warning("picamera2: конфиг %dx%d не подошёл (%s), пробуем 640x480", w, h, e)
        w, h = 640, 480
        cfg = picam2.create_video_configuration(
            main={"size": (w, h), "format": _picam_format},
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
            colour_space="RGB",
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
                        colorspace="RGB",
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


def _start_romeo_aux_services(
    romeo_control_port: int,
    romeo_usb_port: str | None,
    romeo_baud: int,
    romeo_open_delay: float,
    romeo_tank_speed: int,
    romeo_turret_step: int | float | None,
    romeo_led_interval_sec: float,
    romeo_adc_interval_sec: float,
    camera_control_handler: Callable[[dict], dict | None] | None = None,
) -> None:
    usb = romeo_usb_port or ROMEO_USB_PORT
    if romeo_control_port > 0:
        start_romeo_control_server(
            romeo_control_port,
            romeo_port=usb,
            baud=romeo_baud,
            open_delay=romeo_open_delay,
            tank_speed=romeo_tank_speed,
            turret_step_default=romeo_turret_step,
            camera_control_handler=camera_control_handler,
        )
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
    video_mode: str = "jpeg_tcp",
    video_bitrate: int = 40_000_000,
    video_intra: int = 15,
    video_profile: str | None = "high",
    video_level: str | None = None,
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
    ????????? ????? ??? ??????????? ?? Pi: UDP discovery + ???????? TCP,
    ????? ???? H.264/TCP ????? ????????? ??????? Pi, ???? legacy MJPEG/JPEG ?? TCP.
    """
    ctl_advertise = romeo_control_port if romeo_control_port > 0 else None
    if video_mode == "h264_tcp":
        _check_listen_bind_available(tcp_port)
    if discover_port is not None:
        try:
            _start_discovery_responder(
                discover_port,
                tcp_port,
                http_advertise,
                discover_token,
                control_tcp_port=ctl_advertise,
                video_transport="tcp",
                video_codec="h264" if video_mode == "h264_tcp" else "jpeg",
                video_mode=video_mode,
            )
        except OSError:
            sys.exit(1)
        log.info(
            "????? listen: UDP discovery ?? ????? %s, ???? handshake ? LAN%s",
            discover_port,
            " (????? --discover-token ?? ???????)" if discover_token else "",
        )
    else:
        log.info("????? listen: UDP discovery ???????? (--no-discovery)")

    log.info("send: ????? ???????=%s", capture_mode)

    camera_controls = _CameraControlState() if video_mode == "h264_tcp" else None
    camera_control_handler = _make_camera_control_handler(camera_controls) if camera_controls is not None else None

    _start_romeo_aux_services(
        romeo_control_port,
        romeo_usb_port,
        romeo_baud,
        romeo_open_delay,
        romeo_tank_speed,
        romeo_turret_step,
        romeo_led_interval_sec,
        romeo_adc_interval_sec,
        camera_control_handler=camera_control_handler,
    )

    if video_mode == "h264_tcp":
        if overlay_timestamp:
            log.error("H.264/TCP ?? ???????????? --timestamp. ??????????? --video-mode jpeg_tcp ??? overlay.")
            sys.exit(2)
        if capture_mode == "opencv":
            log.warning("H.264/TCP ?????????? --capture opencv ? ?????????? ????????? libcamera/rpicam ????.")
        if camera_device:
            log.warning("H.264/TCP ?????????? --camera-device (???????? ????? libcamera/rpicam, ?? ????? OpenCV).")
        if capture_backend != "auto":
            log.warning("H.264/TCP ?????????? --capture-backend (???????? ????? libcamera/rpicam).")
        log.info("send: ????? ?????=%s", video_mode)
        _run_h264_tcp_listen(
            tcp_port,
            width,
            height,
            fps,
            video_bitrate,
            video_intra,
            video_profile,
            video_level,
            camera_controls=camera_controls,
        )
        return

    tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_srv.bind(("0.0.0.0", tcp_port))
    except OSError as e:
        log.error("TCP: ?? ??????? bind 0.0.0.0:%s: %s", tcp_port, e)
        en = getattr(e, "errno", None)
        if en == errno.EADDRINUSE or "Address already in use" in str(e):
            log.error(
                "???? %s ????? (????? ?????????? ?????? ?? ??????). ????????: fuser -v %s/tcp "
                "??? ss -tlnp '( sport = :%s )'; ?????????: kill <pid> ??? sudo fuser -k %s/tcp",
                tcp_port,
                tcp_port,
                tcp_port,
                tcp_port,
            )
        raise TcpBindError from e
    tcp_srv.listen(5)
    log.info("TCP: ??????? 0.0.0.0:%s, ???? ??????? (Ctrl+C ? ?????)", tcp_port)

    while True:
        conn, addr = tcp_srv.accept()
        _tune_stream_socket(conn)
        log.info("TCP: ???????? ??????????? ? %s:%s", addr[0], addr[1])

        if capture_mode == "picamera2":
            log.info("??????: ????? picamera2 (libcamera), %dx%d", width, height)
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
                log.warning("TCP: ?????? ?????????? (BrokenPipe)")
            except ImportError:
                log.error(
                    "??????????: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
                )
            finally:
                conn.close()
                log.info("?????? ?????????, ????? ???????? ??????? ?? TCP %s ...", tcp_port)
            continue

        cap, first_fr = _try_opencv_capture(
            camera, camera_device, capture_backend, width, height, fps, set_fps
        )
        if cap is None and capture_mode == "auto":
            log.info("OpenCV ?? ??? ???? ? ???????????? ?? picamera2 (??????? ??? Pi 5 + libcamera)")
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
                log.warning("TCP: ?????? ?????????? (BrokenPipe)")
            except ImportError:
                log.error(
                    "??????????: sudo apt install -y python3-libcamera libcap2-dev && pip install picamera2"
                )
            finally:
                conn.close()
                log.info("?????? ?????????, ????? ???????? ??????? ?? TCP %s ...", tcp_port)
            continue

        if cap is None:
            log.error(
                "??????: OpenCV ?? ??? ????. ?? Pi 5: --capture picamera2 ??? --capture auto, "
                "pip install picamera2 ? python3-libcamera."
            )
            conn.close()
            continue

        try:
            _camera_stream_to_socket(
                conn, cap, jpeg_quality, overlay_timestamp, first_fr, jpeg_tcp_queue_depth=jpeg_tcp_queue_depth
            )
        except BrokenPipeError:
            log.warning("TCP: ?????? ?????????? (BrokenPipe)")
        finally:
            cap.release()
            conn.close()
            log.info("?????? ?????????, ????? ???????? ??????? ?? TCP %s ...", tcp_port)


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
    video_mode: str = "auto",
    video_bitrate: int = 40_000_000,
    video_intra: int = 15,
    video_profile: str | None = "high",
    video_level: str | None = None,
    rtsp_path: str = "/camera",
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
    resolved_video_mode = video_mode.strip().lower()
    if resolved_video_mode == "auto":
        resolved_video_mode = _default_video_mode(listen, overlay_timestamp, host)
    if resolved_video_mode not in ("h264_tcp", "udp_h264", "rtp_h264", "rtsp_h264", "jpeg_tcp"):
        log.error("Неизвестный --video-mode: %s", video_mode)
        sys.exit(2)
    if resolved_video_mode == "rtp_h264":
        log.warning(
            "RTP H.264 в текущем стеке пока нестабилен для Windows/GStreamer; "
            "временно используем стабильный режим udp_h264 (MPEG-TS/UDP)."
        )
        resolved_video_mode = "udp_h264"
    if resolved_video_mode in ("udp_h264", "rtp_h264") and listen:
        log.error(
            "UDP/RTP H.264 не поддерживает --listen: Pi должна отправлять поток на адрес ПК. "
            "Используйте --host <ip_пк> без --listen."
        )
        sys.exit(2)
    if resolved_video_mode == "rtsp_h264":
        if overlay_timestamp:
            log.error("RTSP H.264 ?? ???????????? --timestamp. ??????????? --video-mode jpeg_tcp ??? overlay.")
            sys.exit(2)
        if listen:
            log.warning("RTSP H.264 ????????? ?????? ?? Pi; --listen ????????????.")
        if host.strip().lower() not in ("auto", "discover"):
            log.warning(
                "RTSP H.264 ?????????? --host: ??????? ???? ???????????? ? Pi ?? rtsp://<pi-ip>:%s%s",
                port,
                _normalize_rtsp_mount_path(rtsp_path),
            )
        if capture_mode == "opencv":
            log.warning("RTSP H.264 ?????????? --capture opencv ? ?????????? ????????? libcamera/rpicam ????.")
        if camera_device:
            log.warning("RTSP H.264 ?????????? --camera-device (???????? ????? libcamera/rpicam, ?? ????? OpenCV).")
        if capture_backend != "auto":
            log.warning("RTSP H.264 ?????????? --capture-backend (???????? ????? libcamera/rpicam).")
        _start_romeo_aux_services(
            romeo_control_port,
            romeo_usb_port,
            romeo_baud,
            romeo_open_delay,
            romeo_tank_speed,
            romeo_turret_step,
            romeo_led_interval_sec,
            romeo_adc_interval_sec,
            camera_control_handler=None,
        )
        log.info("send: ????? ?????=%s", resolved_video_mode)
        _run_h264_rtsp_server(
            port,
            rtsp_path,
            width,
            height,
            fps,
            video_bitrate,
            video_intra,
            video_profile,
            video_level,
        )
        return
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
            video_mode=resolved_video_mode,
            video_bitrate=video_bitrate,
            video_intra=video_intra,
            video_profile=video_profile,
            video_level=video_level,
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

    if resolved_video_mode == "h264_tcp":
        log.error(
            "H.264/TCP сейчас поддерживается только в режиме --listen (Pi слушает, ПК подключается player'ом). "
            "Для старого push/discovery режима используйте --video-mode jpeg_tcp."
        )
        sys.exit(2)
    if resolved_video_mode == "udp_h264":
        if overlay_timestamp:
            log.error("UDP H.264 не поддерживает --timestamp. Используйте --video-mode jpeg_tcp для overlay.")
            sys.exit(2)
        if host.strip().lower() in ("auto", "discover"):
            log.error(
                "UDP H.264 требует явный --host <ip_пк>, потому что обычный ffplay/VLC не отвечают на текущий discovery."
            )
            sys.exit(2)
        if capture_mode == "opencv":
            log.warning("UDP H.264 игнорирует --capture opencv и использует системный libcamera/rpicam путь.")
        if camera_device:
            log.warning("UDP H.264 игнорирует --camera-device (работает через libcamera/rpicam, не через OpenCV).")
        if capture_backend != "auto":
            log.warning("UDP H.264 игнорирует --capture-backend (работает через libcamera/rpicam).")
        camera_controls = _CameraControlState()
        camera_control_handler = _make_camera_control_handler(camera_controls)
        _start_romeo_aux_services(
            romeo_control_port,
            romeo_usb_port,
            romeo_baud,
            romeo_open_delay,
            romeo_tank_speed,
            romeo_turret_step,
            romeo_led_interval_sec,
            romeo_adc_interval_sec,
            camera_control_handler=camera_control_handler,
        )
        log.info("send: режим видео=%s", resolved_video_mode)
        _run_h264_udp_push(
            host,
            port,
            width,
            height,
            fps,
            video_bitrate,
            video_intra,
            video_profile,
            video_level,
            camera_controls=camera_controls,
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

    log.info("send: режим видео=%s, режим захвата=%s", resolved_video_mode, capture_mode)

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
