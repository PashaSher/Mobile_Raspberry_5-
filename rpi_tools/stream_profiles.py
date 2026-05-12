"""Пресеты разрешения / FPS / битрейта для `stream_camera send`."""

from __future__ import annotations

from typing import Any

# Ключ — имя `--stream-preset`; значения подставляются в argparse до вызова run_send.
STREAM_PRESETS: dict[str, dict[str, Any]] = {
    # Основной режим: 1080p30, высокий H.264 битрейт и умеренный GOP.
    "broadcast": {
        "width": 1920,
        "height": 1080,
        "fps": 30.0,
        "video_bitrate": 30_000_000,
        "video_intra": 15,
        "video_profile": "high",
        "jpeg_quality": 92,
        "jpeg_chroma": "422",
        "jpeg_threads": 8,
        "jpeg_fast_dct": True,
    },
    # Максимум качества: тот же 1080p, но ниже FPS и заметно выше битрейт.
    "cinema": {
        "width": 1920,
        "height": 1080,
        "fps": 24.0,
        "video_bitrate": 50_000_000,
        "video_intra": 12,
        "video_profile": "high",
        "jpeg_quality": 95,
        "jpeg_chroma": "444",
        "jpeg_threads": 6,
        "jpeg_fast_dct": False,
    },
    # Для более узкого канала: 720p30 и заметно меньше битрейт.
    "mobile": {
        "width": 1280,
        "height": 720,
        "fps": 30.0,
        "video_bitrate": 8_000_000,
        "video_intra": 15,
        "video_profile": "main",
        "jpeg_quality": 88,
        "jpeg_chroma": "420",
        "jpeg_threads": 6,
        "jpeg_fast_dct": True,
    },
    # Агрессивный low-latency режим для UDP/Wi-Fi управления по видео.
    "realtime": {
        "width": 960,
        "height": 540,
        "fps": 30.0,
        "video_bitrate": 4_000_000,
        "video_intra": 10,
        "video_profile": "main",
        "jpeg_quality": 82,
        "jpeg_chroma": "420",
        "jpeg_threads": 4,
        "jpeg_fast_dct": True,
    },
}


def apply_stream_preset(args: Any) -> None:
    """Подставляет поля пресета в namespace argparse (мутирует args)."""
    name = getattr(args, "stream_preset", None) or "custom"
    # Для UDP/RTP low-latency режима "broadcast" по умолчанию слишком тяжёлый:
    # автоматически переходим на realtime, если пользователь не ушёл в custom.
    if getattr(args, "video_mode", None) in ("udp_h264", "rtp_h264") and name == "broadcast":
        name = "realtime"
    if name == "custom" or name not in STREAM_PRESETS:
        return
    p = STREAM_PRESETS[name]
    for k, v in p.items():
        if k == "jpeg_fast_dct":
            setattr(args, "no_jpeg_fast_dct", not bool(v))
        else:
            setattr(args, k, v)
