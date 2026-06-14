#!/usr/bin/env python3
"""Pi → VPS: лёгкий PCM-поток (16 kHz mono) отдельно от WebRTC видео."""

from __future__ import annotations

import http.client
import logging
import os
import subprocess
import sys
import time
import urllib.parse

log = logging.getLogger("pi.audio_relay")

SAMPLE_RATE = 16_000
CHANNELS = 1
BYTES_PER_SAMPLE = 2
FRAME_MS = 20
CHUNK_BYTES = SAMPLE_RATE * CHANNELS * BYTES_PER_SAMPLE * FRAME_MS // 1000  # 640


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def resolve_alsa_device() -> str:
    override = _env("WEBRTC_AUDIO_ALSA") or _env("AUDIO_RELAY_ALSA")
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


def _parse_publish_url(raw: str) -> tuple[str, int, str]:
    u = urllib.parse.urlparse(raw)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    return host, port, path


def _chunked_publish(host: str, port: int, path: str, token: str, proc: subprocess.Popen[bytes]) -> None:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
        "Transfer-Encoding": "chunked",
        "Connection": "close",
    }
    conn = http.client.HTTPConnection(host, port, timeout=30)
    conn.putrequest("POST", path)
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()

    stdout = proc.stdout
    if not stdout:
        raise RuntimeError("arecord stdout missing")

    total = 0
    try:
        while True:
            data = stdout.read(CHUNK_BYTES)
            if not data:
                break
            conn.send(f"{len(data):x}\r\n".encode("ascii"))
            conn.send(data)
            conn.send(b"\r\n")
            total += len(data)
    finally:
        try:
            conn.send(b"0\r\n\r\n")
            resp = conn.getresponse()
            resp.read()
            log.info("publish ended: %d bytes, HTTP %s", total, resp.status)
        except Exception as exc:
            log.debug("publish close: %s", exc)
        conn.close()


def run_once(publish_url: str, token: str, device: str) -> None:
    host, port, path = _parse_publish_url(publish_url)
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
    log.info("arecord %s → %s", device, publish_url)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _chunked_publish(host, port, path, token, proc)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        err = (proc.stderr.read() if proc.stderr else b"").decode(errors="replace").strip()
        if err:
            log.warning("arecord stderr: %s", err[:300])


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    room = _env("WEBRTC_ROOM", "pi-camera") or "pi-camera"
    base = _env("AUDIO_RELAY_URL") or _env("WEBRTC_SIGNAL_URL", "").replace("/api/signal", "/api/audio-relay")
    if not base:
        base = "http://116.203.148.254/api/audio-relay"
    base = base.rstrip("/")
    publish_url = _env("AUDIO_RELAY_PUBLISH_URL") or f"{base}/rooms/{room}/publish"
    token = _env("ICE_CONFIG_TOKEN")
    if not token:
        log.error("ICE_CONFIG_TOKEN required")
        return 1
    device = resolve_alsa_device()
    backoff = 2.0
    while True:
        try:
            run_once(publish_url, token, device)
        except KeyboardInterrupt:
            log.info("stop")
            return 0
        except Exception as exc:
            log.warning("relay error: %s — retry in %.0fs", exc, backoff)
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 30.0)


if __name__ == "__main__":
    sys.exit(main())
