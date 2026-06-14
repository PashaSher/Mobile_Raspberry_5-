"""I2S/ALSA аудио для WebRTC: микрофон Pi → браузер (лёгкий режим, не блокирует видео)."""

from __future__ import annotations

import asyncio
import fractions
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiortc import MediaStreamTrack

log = logging.getLogger("camstream.webrtc.audio")

_DEFAULT_SAMPLE_RATE = 48_000
_DEFAULT_CHANNELS = 1
_WEBRTC_FRAME_SAMPLES = 960  # 20 ms @ 48 kHz (стандарт WebRTC/Opus)


def _make_silent_track(sample_rate: int = _DEFAULT_SAMPLE_RATE) -> "MediaStreamTrack":
    from aiortc.mediastreams import MediaStreamTrack
    from av import AudioFrame

    samples_per_frame = _WEBRTC_FRAME_SAMPLES if sample_rate == _DEFAULT_SAMPLE_RATE else max(160, sample_rate // 50)

    class SilentAudioTrack(MediaStreamTrack):
        kind = "audio"

        def __init__(self) -> None:
            super().__init__()
            self._timestamp = 0

        async def recv(self):
            await asyncio.sleep(samples_per_frame / sample_rate)
            frame = AudioFrame(format="s16", layout="mono", samples=samples_per_frame)
            frame.sample_rate = sample_rate
            frame.planes[0].update(b"\x00" * (samples_per_frame * 2))
            frame.pts = self._timestamp
            self._timestamp += samples_per_frame
            frame.time_base = fractions.Fraction(1, sample_rate)
            return frame

    return SilentAudioTrack()


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


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


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


def create_push_to_listen_track(bridge: "WebRTCAudioBridge") -> "MediaStreamTrack":
    from aiortc.mediastreams import MediaStreamTrack

    class PushToListenTrack(MediaStreamTrack):
        kind = "audio"

        def __init__(self) -> None:
            super().__init__()
            self._bridge = bridge
            self._listening = False
            self._mic: MediaStreamTrack | None = None
            self._timestamp = 0
            self._resampler = None

        def set_listen(self, on: bool) -> bool:
            if on:
                if self._listening:
                    return True
                mic = self._bridge.start_capture()
                if mic is None:
                    return False
                self._mic = mic
                self._listening = True
                self._resampler = None
                log.info("WebRTC audio: push-to-listen ON")
                return True
            if not self._listening:
                return True
            self._listening = False
            self._bridge.stop_capture()
            self._mic = None
            self._resampler = None
            log.info("WebRTC audio: push-to-listen OFF")
            return True

        def _silent_frame(self):
            from av import AudioFrame

            frame = AudioFrame(format="s16", layout="mono", samples=_WEBRTC_FRAME_SAMPLES)
            frame.sample_rate = _DEFAULT_SAMPLE_RATE
            frame.planes[0].update(b"\x00" * (_WEBRTC_FRAME_SAMPLES * 2))
            frame.pts = self._timestamp
            self._timestamp += _WEBRTC_FRAME_SAMPLES
            frame.time_base = fractions.Fraction(1, _DEFAULT_SAMPLE_RATE)
            return frame

        def _normalize_frame(self, frame):
            from av import AudioFrame
            from av.audio.resampler import AudioResampler

            if (
                frame.sample_rate == _DEFAULT_SAMPLE_RATE
                and frame.layout.name == "mono"
                and frame.format.name == "s16"
            ):
                frame.pts = self._timestamp
                self._timestamp += frame.samples
                frame.time_base = fractions.Fraction(1, _DEFAULT_SAMPLE_RATE)
                return frame
            if self._resampler is None:
                self._resampler = AudioResampler(
                    format="s16", layout="mono", rate=_DEFAULT_SAMPLE_RATE
                )
            converted = self._resampler.resample(frame)
            if not converted:
                return self._silent_frame()
            out = converted[0] if isinstance(converted, list) else converted
            if not isinstance(out, AudioFrame):
                return self._silent_frame()
            out.pts = self._timestamp
            self._timestamp += out.samples
            out.time_base = fractions.Fraction(1, _DEFAULT_SAMPLE_RATE)
            return out

        async def recv(self):
            if self._listening and self._mic is not None:
                try:
                    raw = await self._mic.recv()
                    return self._normalize_frame(raw)
                except Exception as exc:
                    log.warning("WebRTC audio: mic recv: %s", exc)
                    self.set_listen(False)
            await asyncio.sleep(_WEBRTC_FRAME_SAMPLES / _DEFAULT_SAMPLE_RATE)
            return self._silent_frame()

    return PushToListenTrack()


class WebRTCAudioBridge:
    """Захват с I2S-микрофона; воспроизведение браузера → усилитель (опционально)."""

    def __init__(
        self,
        *,
        alsa_device: str | None = None,
        sample_rate: int | None = None,
        channels: int | None = None,
        enabled: bool | None = None,
        playback_enabled: bool | None = None,
    ) -> None:
        self._enabled = _env_bool("WEBRTC_AUDIO", False) if enabled is None else enabled
        self._playback_enabled = (
            _env_bool("WEBRTC_AUDIO_PLAYBACK", False)
            if playback_enabled is None
            else playback_enabled
        )
        self._alsa = (alsa_device or "").strip() or resolve_alsa_device()
        self._sample_rate = max(
            8_000,
            sample_rate if sample_rate is not None else _env_int(
                "WEBRTC_AUDIO_SAMPLE_RATE", _DEFAULT_SAMPLE_RATE
            ),
        )
        self._channels = max(
            1,
            min(
                2,
                channels if channels is not None else _env_int(
                    "WEBRTC_AUDIO_CHANNELS", _DEFAULT_CHANNELS
                ),
            ),
        )
        self._player = None
        self._recorder = None
        self._capture_track: MediaStreamTrack | None = None
        self._capture_started = False
        self._silent_track: MediaStreamTrack | None = None
        self._push_track: MediaStreamTrack | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def playback_enabled(self) -> bool:
        return self._playback_enabled

    @property
    def alsa_device(self) -> str:
        return self._alsa

    def get_push_to_listen_track(self) -> "MediaStreamTrack":
        if self._push_track is None:
            self._push_track = create_push_to_listen_track(self)
        return self._push_track

    def reset_push_to_listen_track(self) -> None:
        if self._push_track is not None:
            try:
                self._push_track.set_listen(False)
            except Exception:
                pass
        self._push_track = None

    def get_silent_track(self) -> "MediaStreamTrack":
        if self._silent_track is None:
            self._silent_track = _make_silent_track(self._sample_rate)
        return self._silent_track

    def _alsa_options(self) -> dict[str, str]:
        # Меньший буфер и 16 kHz mono — меньше нагрузка на Pi и TURN relay.
        return {
            "channels": str(self._channels),
            "sample_rate": str(self._sample_rate),
            "buffer_size": os.environ.get("WEBRTC_AUDIO_BUFFER_SIZE", "4096"),
            "period_size": os.environ.get("WEBRTC_AUDIO_PERIOD_SIZE", "512"),
        }

    def start_capture(self) -> MediaStreamTrack | None:
        """Микрофон Pi → WebRTC send track (только если браузер запросил m=audio)."""
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

        # Ранний старт worker — иначе XRUN на Voice HAT до первого recv().
        if not self._capture_started:
            self._player._start(self._capture_track)
            self._capture_started = True

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
        self._capture_started = False

    async def stop_playback(self) -> None:
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
            self._recorder = None

    async def stop(self) -> None:
        self.reset_push_to_listen_track()
        self.stop_capture()
        await self.stop_playback()


def apply_low_priority_audio_sdp(sdp: str) -> str:
    """Opus mono ~16 kbit/s — меньше нагрузка на Pi и TURN, видео в приоритете."""
    import re

    max_br = str(_env_int("WEBRTC_AUDIO_MAX_BITRATE", 16_000))
    cap_rate = str(_env_int("WEBRTC_AUDIO_SAMPLE_RATE", _DEFAULT_SAMPLE_RATE))
    opus_pts: set[str] = set()
    for line in sdp.splitlines():
        m = re.match(r"a=rtpmap:(\d+) opus/", line, re.I)
        if m:
            opus_pts.add(m.group(1))
    if not opus_pts:
        return sdp

    extra = f"maxaveragebitrate={max_br};stereo=0;sprop-maxcapturerate={cap_rate}"
    out: list[str] = []
    for line in sdp.splitlines():
        if line.startswith("a=fmtp:"):
            pt = line[7:].split()[0]
            if pt in opus_pts and "maxaveragebitrate" not in line:
                sep = ";" if ";" in line or "=" in line.split(":", 1)[-1] else ";"
                line = f"{line}{sep}{extra}"
        out.append(line)
    body = "\r\n".join(out)
    return body + ("\r\n" if not body.endswith("\r\n") else "")


async def limit_audio_sender_bitrate(sender: Any, *, max_bitrate: int | None = None) -> None:
    """Ограничить RTP bitrate аудио-отправителя (aiortc)."""
    br = max(8_000, max_bitrate or _env_int("WEBRTC_AUDIO_MAX_BITRATE", 16_000))
    try:
        params = sender.getParameters()
        if not params.encodings:
            params.encodings = [{}]
        for enc in params.encodings:
            enc["maxBitrate"] = br
        await sender.setParameters(params)
        log.info("WebRTC audio: sender maxBitrate=%d bps", br)
    except Exception as exc:
        log.debug("WebRTC audio: limit sender bitrate: %s", exc)
