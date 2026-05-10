"""Пресеты разрешения / FPS / JPEG для `stream_camera send` (передача «как в эфире»)."""

from __future__ import annotations

from typing import Any

# Ключ — имя `--stream-preset`; значения подставляются в argparse до вызова run_send.
STREAM_PRESETS: dict[str, dict[str, Any]] = {
    # Баланс битрейта и детализации (720p30, 4:2:2 — меньше трафика, чем 4:4:4 при том же FPS).
    "broadcast": {
        "width": 1280,
        "height": 720,
        "fps": 30.0,
        "jpeg_quality": 92,
        "jpeg_chroma": "422",
        "jpeg_threads": 8,
        "jpeg_fast_dct": True,
    },
    # Максимум детализации цвета и битрейта; чуть ниже частота кадров — типичный «кино»-ритм.
    "cinema": {
        "width": 1280,
        "height": 720,
        "fps": 24.0,
        "jpeg_quality": 95,
        "jpeg_chroma": "444",
        "jpeg_threads": 6,
        "jpeg_fast_dct": False,
    },
    # Узкий Wi‑Fi / стабильность потока важнее разрешения.
    "mobile": {
        "width": 960,
        "height": 540,
        "fps": 30.0,
        "jpeg_quality": 88,
        "jpeg_chroma": "420",
        "jpeg_threads": 6,
        "jpeg_fast_dct": True,
    },
}


def apply_stream_preset(args: Any) -> None:
    """Подставляет поля пресета в namespace argparse (мутирует args)."""
    name = getattr(args, "stream_preset", None) or "custom"
    if name == "custom" or name not in STREAM_PRESETS:
        return
    p = STREAM_PRESETS[name]
    for k, v in p.items():
        if k == "jpeg_fast_dct":
            setattr(args, "no_jpeg_fast_dct", not bool(v))
        else:
            setattr(args, k, v)
