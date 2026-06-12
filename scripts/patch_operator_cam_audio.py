#!/usr/bin/env python3
"""Патч страницы оператора VPS: duplex audio (Pi mic ↔ браузер ↔ Pi speaker)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deploy" / "vps" / "webrtc-client_with_audio.html"


def patch(html: str) -> str:
    if "localAudioStream" in html:
        return html

    html = html.replace(
        '<video id="remoteVideo" autoplay playsinline muted></video>',
        '<video id="remoteVideo" autoplay playsinline muted></video>\n'
        '                <audio id="remoteAudio" autoplay playsinline></audio>',
    )

    html = html.replace(
        "        let pc = null;",
        "        let pc = null;\n        let localAudioStream = null;",
    )

    old_ontrack = """            pc.ontrack = async (event) => {
                const track = event.track;
                log("Received remote track: " + track.kind + ", id=" + track.id, "success");
                if (track.kind === "video") {
                    log(
                        "Video codec hint: check Pi sends H.264 baseline/profile browsers can decode (not HEVC-only)",
                        "info",
                    );
                    queueMicrotask(() => applyLowLatencyVideoHints());
                }
                track.enabled = true;
                track.onmute = () => log("Remote track muted", "warn");
                track.onunmute = () => log("Remote track unmuted", "success");
                track.onended = () => log("Remote track ended", "error");

                const video = document.getElementById("remoteVideo");
                const stream =
                    event.streams && event.streams[0]
                        ? event.streams[0]
                        : new MediaStream([track]);
                video.srcObject = stream;
                if (typeof video.requestVideoFrameCallback === "function") {
                    video.requestVideoFrameCallback(() =>
                        log("Отрисован кадр в <video> (requestVideoFrameCallback)", "success"),
                    );
                }
                try {
                    await video.play();
                    log("video.play() OK", "success");
                } catch (e) {
                    log("video.play() failed: " + (e && e.message ? e.message : String(e)), "error");
                }
            };"""

    new_ontrack = """            pc.ontrack = async (event) => {
                const track = event.track;
                log("Received remote track: " + track.kind + ", id=" + track.id, "success");
                track.enabled = true;
                track.onmute = () => log("Remote track muted", "warn");
                track.onunmute = () => log("Remote track unmuted", "success");
                track.onended = () => log("Remote track ended", "error");

                if (track.kind === "audio") {
                    const audio = document.getElementById("remoteAudio");
                    audio.srcObject = new MediaStream([track]);
                    try {
                        await audio.play();
                        log("Pi mic → browser audio.play() OK", "success");
                    } catch (e) {
                        log("remoteAudio.play(): " + (e && e.message ? e.message : String(e)), "error");
                    }
                    return;
                }

                if (track.kind === "video") {
                    log(
                        "Video codec hint: check Pi sends H.264 baseline/profile browsers can decode (not HEVC-only)",
                        "info",
                    );
                    queueMicrotask(() => applyLowLatencyVideoHints());
                }

                const video = document.getElementById("remoteVideo");
                const stream =
                    event.streams && event.streams[0]
                        ? event.streams[0]
                        : new MediaStream([track]);
                video.srcObject = stream;
                if (typeof video.requestVideoFrameCallback === "function") {
                    video.requestVideoFrameCallback(() =>
                        log("Отрисован кадр в <video> (requestVideoFrameCallback)", "success"),
                    );
                }
                try {
                    await video.play();
                    log("video.play() OK", "success");
                } catch (e) {
                    log("video.play() failed: " + (e && e.message ? e.message : String(e)), "error");
                }
            };"""

    if old_ontrack not in html:
        raise SystemExit("patch_operator_cam_audio: ontrack block not found — VPS page changed?")
    html = html.replace(old_ontrack, new_ontrack)

    old_tx = """            const videoTransceiver = pc.addTransceiver("video", { direction: "recvonly" });
            preferH264Receive(videoTransceiver);"""

    new_tx = """            const videoTransceiver = pc.addTransceiver("video", { direction: "recvonly" });
            preferH264Receive(videoTransceiver);

            const audioTransceiver = pc.addTransceiver("audio", { direction: "sendrecv" });
            try {
                localAudioStream = await navigator.mediaDevices.getUserMedia({
                    audio: {
                        echoCancellation: true,
                        noiseSuppression: true,
                        autoGainControl: true,
                    },
                    video: false,
                });
                const micTrack = localAudioStream.getAudioTracks()[0];
                if (micTrack) {
                    await audioTransceiver.sender.replaceTrack(micTrack);
                    log("Browser mic → Pi speaker", "success");
                }
            } catch (e) {
                log(
                    "getUserMedia(audio): " + (e && e.message ? e.message : String(e)) +
                        " — только приём с Pi",
                    "warn",
                );
                try {
                    audioTransceiver.direction = "recvonly";
                } catch (_) {}
            }"""

    if old_tx not in html:
        raise SystemExit("patch_operator_cam_audio: transceiver block not found")
    html = html.replace(old_tx, new_tx)

    old_hangup = """            document.getElementById("remoteVideo").srcObject = null;

            const rp = lastSignalingRoomPath || getRoomPath();"""

    new_hangup = """            document.getElementById("remoteVideo").srcObject = null;
            const remoteAudio = document.getElementById("remoteAudio");
            if (remoteAudio) {
                remoteAudio.srcObject = null;
            }
            if (localAudioStream) {
                localAudioStream.getTracks().forEach((t) => t.stop());
                localAudioStream = null;
            }

            const rp = lastSignalingRoomPath || getRoomPath();"""

    if old_hangup not in html:
        raise SystemExit("patch_operator_cam_audio: hangup block not found")
    html = html.replace(old_hangup, new_hangup)

    return html


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if src is None:
        import urllib.request

        url = "http://116.203.148.254/webrtc-client.html"
        with urllib.request.urlopen(url, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    else:
        html = src.read_text(encoding="utf-8")

    patched = patch(html)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(patched, encoding="utf-8")
    print(f"OK: {OUT}")
    print(f"Deploy на VPS: scp {OUT} → /var/www/html/webrtc-client.html (или ваш nginx root)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
