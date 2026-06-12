"""I2S/ALSA аудио для WebRTC: микрофон Pi → браузер, микрофон браузера → усилитель."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiortc import MediaStreamTrack

log = logging.getLogger("camstream.webrtc.audio")


def _ensure_alsa_config() -> None:
    """PyAV/ffmpeg ищет alsa.conf в /tmp/vendor — на Pi задаём системный путь."""
    if os.environ.get("ALSA_CONFIG_PATH"):
        return
    for path in ("/usr/share/alsa/alsa.conf", "/etc/asound.conf"):
        if os.path.isfile(path):
            os.environ["ALSA_CONFIG_PATH"] = path
            return


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw not in ("0", "false", "no", "off")


def resolve_alsa_device() -> str:
    """plughw:N,0 для googlevoicehat или WEBRTC_AUDIO_ALSA."""
    override = os.environ.get("WEBRTC_AUDIO_ALSA", "").strip()
    if override:
        return override
    try:
        with open("/proc/asound/cards", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                low = line.lower()
                if "voice" not in low and "googlevoi" not in low:
                    continue
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    return f"plughw:{parts[0]},0"
    except OSError as exc:
        log.debug("resolve_alsa_device: %s", exc)
    return "default"


class WebRTCAudioBridge:
    """Захват с I2S-микрофона и воспроизведение удалённого аудио на усилитель."""

    def __init__(
        self,
        *,
        alsa_device: str | None = None,
        sample_rate: int = 48_000,
        channels: int = 1,
        enabled: bool | None = None,
        playback_enabled: bool | None = None,
    ) -> None:
        self._enabled = _env_bool("WEBRTC_AUDIO", True) if enabled is None else enabled
        self._playback_enabled = (
            _env_bool("WEBRTC_AUDIO_PLAYBACK", True)
            if playback_enabled is None
            else playback_enabled
        )
        self._alsa = (alsa_device or "").strip() or resolve_alsa_device()
        self._sample_rate = max(8_000, int(sample_rate))
        self._channels = max(1, min(2, int(channels)))
        self._player = None
        self._recorder = None
        self._capture_track: MediaStreamTrack | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def playback_enabled(self) -> bool:
        return self._playback_enabled

    @property
    def alsa_device(self) -> str:
        return self._alsa

    def _alsa_options(self) -> dict[str, str]:
        return {
            "channels": str(self._channels),
            "sample_rate": str(self._sample_rate),
            "buffer_size": "8192",
            "period_size": "1024",
        }

    def start_capture(self) -> MediaStreamTrack | None:
        """Микрофон Pi → WebRTC send track."""
        if not self._enabled:
            return None
        _ensure_alsa_config()
        from aiortc.contrib.media import MediaPlayer

        self.stop_capture()
        try:
            self._player = MediaPlayer(
                self._alsa,
                format="alsa",
                options=self._alsa_options(),
            )
        except Exception as exc:
            log.error(
                "WebRTC audio: не удалось открыть захват %s: %s",
                self._alsa,
                exc,
            )
            self._player = None
            return None

        self._capture_track = self._player.audio
        if self._capture_track is None:
            log.error("WebRTC audio: MediaPlayer не дал audio track (%s)", self._alsa)
            self.stop_capture()
            return None

        # av.open(alsa) сразу пишет в DMA-буфер; worker thread стартует только в recv().
        # Без раннего _start() — XRUN и пустой RTP до подключения браузера.
        self._player._start(self._capture_track)

        log.info(
            "WebRTC audio: захват с %s (%s Hz, ch=%s)",
            self._alsa,
            self._sample_rate,
            self._channels,
        )
        return self._capture_track

    async def start_playback(self, track: MediaStreamTrack) -> None:
        """Аудио из браузера → усилитель Pi."""
        if not self._enabled or not self._playback_enabled:
            if self._enabled and not self._playback_enabled:
                log.info("WebRTC audio: воспроизведение отключено (только микрофон)")
            return
        _ensure_alsa_config()
        from aiortc.contrib.media import MediaRecorder

        await self.stop_playback()
        try:
            self._recorder = MediaRecorder(
                self._alsa,
                format="alsa",
                options=self._alsa_options(),
            )
            self._recorder.addTrack(track)
            await self._recorder.start()
            log.info("WebRTC audio: воспроизведение на %s", self._alsa)
        except Exception as exc:
            log.error(
                "WebRTC audio: не удалось открыть вывод %s: %s",
                self._alsa,
                exc,
            )
            await self.stop_playback()

    def stop_capture(self) -> None:
        if self._capture_track is not None:
            try:
                self._capture_track.stop()
            except Exception:
                pass
            self._capture_track = None
        if self._player is not None:
            try:
                if self._player.audio:
                    self._player.audio.stop()
            except Exception:
                pass
            self._player = None

    async def stop_playback(self) -> None:
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
            self._recorder = None

    async def stop(self) -> None:
        self.stop_capture()
        await self.stop_playback()
