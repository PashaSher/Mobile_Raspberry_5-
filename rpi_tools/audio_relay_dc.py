"""Pi → браузер: PCM по отдельному Data Channel (не m=audio, не TURN RTP)."""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import threading
from typing import Any

log = logging.getLogger("camstream.audio_dc")

SAMPLE_RATE = 16_000
CHANNELS = 1
FRAME_BYTES = 640  # 20 ms @ 16 kHz mono s16le
MAGIC = b"\xa1"
_MAX_BUFFERED = 48_000


def dc_audio_enabled() -> bool:
    raw = os.environ.get("AUDIO_RELAY_DC", "1").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return os.environ.get("WEBRTC_AUDIO", "0").strip().lower() in ("0", "false", "no", "off")


def resolve_alsa_device() -> str:
    override = os.environ.get("WEBRTC_AUDIO_ALSA", "").strip() or os.environ.get(
        "AUDIO_RELAY_ALSA", ""
    ).strip()
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
    except OSError:
        pass
    return "default"


class AudioDcRelay:
    """arecord → SCTP Data Channel pi-audio (низкий приоритет, без WebRTC audio track)."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._proc: subprocess.Popen[bytes] | None = None
        self._channel: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(
        self, channel: Any, loop: asyncio.AbstractEventLoop | None = None
    ) -> None:
        self.stop()
        self._channel = channel
        self._loop = loop
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="audio-dc-relay")
        self._thread.start()
        log.info("Audio DC relay: старт (%s Hz, device=%s)", SAMPLE_RATE, resolve_alsa_device())

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._proc = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        self._channel = None
        self._loop = None

    def _send_frame(self, payload: bytes) -> None:
        ch = self._channel
        if ch is None or getattr(ch, "readyState", "") != "open":
            return
        if int(getattr(ch, "bufferedAmount", 0) or 0) > _MAX_BUFFERED:
            return
        ch.send(payload)

    def _run(self) -> None:
        device = resolve_alsa_device()
        cmd = [
            "arecord",
            "-D",
            device,
            "-f",
            "S16_LE",
            "-r",
            str(SAMPLE_RATE),
            "-c",
            str(CHANNELS),
            "-t",
            "raw",
            "-q",
            "-",
        ]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as exc:
            log.error("Audio DC relay: arecord failed: %s", exc)
            return

        stdout = self._proc.stdout
        if not stdout:
            return

        sent = 0
        while not self._stop.is_set():
            chunk = stdout.read(FRAME_BYTES)
            if not chunk:
                break
            ch = self._channel
            if ch is None:
                break
            payload = MAGIC + chunk
            loop = self._loop
            try:
                if loop and loop.is_running():
                    loop.call_soon_threadsafe(self._send_frame, payload)
                    sent += 1
                elif getattr(ch, "readyState", "") == "open":
                    self._send_frame(payload)
                    sent += 1
                if sent == 1 or sent % 500 == 0:
                    log.info(
                        "Audio DC relay: frames queued=%d buffered=%d",
                        sent,
                        int(getattr(ch, "bufferedAmount", 0) or 0),
                    )
            except Exception as exc:
                log.warning("Audio DC relay send: %s", exc)
                break

        err = (self._proc.stderr.read() if self._proc.stderr else b"").decode(errors="replace")
        if err.strip():
            log.warning("Audio DC relay arecord: %s", err.strip()[:200])
