"""H.264 camera track for WebRTC: rpicam-vid → RTP (passthrough или decode+re-encode)."""

from __future__ import annotations

import asyncio
import fractions
import logging
import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Optional

import av
from aiortc import MediaStreamTrack
from aiortc.mediastreams import MediaStreamError

log = logging.getLogger("camstream.webrtc")

# Passthrough: несколько NAL на кадр — очередь 1 отбрасывала пакеты → «слайдшоу».
_PASSTHROUGH_QUEUE_MAXSIZE = 16
# Legacy decode→re-encode: маленькая очередь, но libx264 на каждом кадре даёт ~0.5–1.5 с лага.
_DECODE_QUEUE_MAXSIZE = 2

# Первый кадр с rpicam + PyAV на Pi может занимать 10–30+ с; короткий recv-таймаут убивал RTP.
_FIRST_FRAME_RECV_TIMEOUT_SEC = 40.0
_FRAME_RECV_TIMEOUT_SEC = 8.0


def _h264_tool_path() -> str | None:
    for name in ("rpicam-vid", "libcamera-vid"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _build_rpicam_command(
    tool_path: str,
    width: int,
    height: int,
    fps: float,
    bitrate: int,
    intra: int,
    profile: str | None,
    camera_extra_args: list[str] | None = None,
) -> list[str]:
    cmd = [
        tool_path,
        "-t", "0",
        "-n",
        "--codec", "h264",
        "--libav-format", "h264",
        "--inline",
        "--width", str(max(64, int(width))),
        "--height", str(max(64, int(height))),
        "--framerate", f"{max(1.0, float(fps)):g}",
        "--bitrate", str(max(500_000, int(bitrate))),
    ]
    if intra > 0:
        cmd.extend(("--intra", str(max(1, int(intra)))))
    if profile:
        cmd.extend(("--profile", str(profile)))
    if camera_extra_args:
        cmd.extend(camera_extra_args)
    cmd.extend(("-o", "-"))
    return cmd


def _env_h264_passthrough() -> bool:
    v = os.environ.get("CAMSTREAM_WEBRTC_H264_PASSTHROUGH", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def make_h264_track(
    width: int = 1280,
    height: int = 720,
    fps: float = 30.0,
    bitrate: int = 4_000_000,
    intra: int = 30,
    profile: str | None = "high",
    camera_extra_args: list[str] | None = None,
) -> MediaStreamTrack:
    """Passthrough (по умолчанию): rpicam H.264 → av.Packet → RTP без decode/libx264."""
    if _env_h264_passthrough():
        return H264PassthroughTrack(
            width=width,
            height=height,
            fps=fps,
            bitrate=bitrate,
            intra=intra,
            profile=profile,
            camera_extra_args=camera_extra_args,
        )
    log.warning(
        "H264CameraTrack: passthrough выкл (CAMSTREAM_WEBRTC_H264_PASSTHROUGH=0) — "
        "decode+libx264 re-encode, задержка видео +0.5–1.5 с"
    )
    return H264CameraTrack(
        width=width,
        height=height,
        fps=fps,
        bitrate=bitrate,
        intra=intra,
        profile=profile,
        camera_extra_args=camera_extra_args,
    )


class _H264TrackBase(MediaStreamTrack):
    kind = "video"

    def __init__(
        self,
        width: int,
        height: int,
        fps: float,
        bitrate: int,
        intra: int,
        profile: str | None,
        camera_extra_args: list[str] | None,
    ) -> None:
        super().__init__()
        self._width = width
        self._height = height
        self._fps = fps
        self._bitrate = bitrate
        self._intra = intra
        self._profile = profile
        self._camera_extra_args = camera_extra_args or []
        self._proc: subprocess.Popen | None = None
        self._reader_task: asyncio.Task | None = None
        self._started = False
        self._got_first_frame = False
        self._pts = 0
        self._time_base = fractions.Fraction(1, 90000)
        self._pts_step = int(90000 / max(1, fps))
        self._loop: asyncio.AbstractEventLoop | None = None

    def _log_cmd(self, cmd: list[str]) -> None:
        cmd_line = " ".join(cmd)
        log.warning("%s: starting %s", type(self).__name__, cmd_line)
        try:
            from pathlib import Path

            Path("/tmp/camstream_rpicam_cmd.txt").write_text(
                cmd_line + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        print(f"\n>>> rpicam-vid: {cmd_line}\n", flush=True)

    def _log_source_health(self, context: str) -> None:
        proc = self._proc
        if not proc:
            log.warning("%s: %s — нет процесса камеры", type(self).__name__, context)
            return
        rc = proc.poll()
        if rc is not None:
            tail = ""
            if proc.stderr:
                try:
                    tail = proc.stderr.read(4096).decode(errors="replace")
                except Exception:
                    pass
            log.error(
                "%s: %s — rpicam завершился rc=%s stderr=%s",
                type(self).__name__,
                context,
                rc,
                (tail[:1200] if tail else "(пусто)"),
            )
        else:
            log.warning(
                "%s: %s — процесс жив, данных в очереди пока нет",
                type(self).__name__,
                context,
            )

    def stop(self) -> None:
        super().stop()
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            log.info("%s: rpicam-vid stopped", type(self).__name__)


class H264PassthroughTrack(_H264TrackBase):
    """
    rpicam-vid H.264 → av.Packet (demux) → aiortc H264Encoder.pack() без libx264.
    """

    def __init__(
        self,
        width: int = 1280,
        height: int = 720,
        fps: float = 30.0,
        bitrate: int = 4_000_000,
        intra: int = 30,
        profile: str | None = "high",
        camera_extra_args: list[str] | None = None,
    ) -> None:
        super().__init__(
            width, height, fps, bitrate, intra, profile, camera_extra_args,
        )
        self._demux_thread: threading.Thread | None = None
        self._packet_q: queue.Queue[av.Packet | None] = queue.Queue(
            maxsize=_PASSTHROUGH_QUEUE_MAXSIZE,
        )
        self._queue: asyncio.Queue[av.Packet] = asyncio.Queue(
            maxsize=_PASSTHROUGH_QUEUE_MAXSIZE,
        )
        self._packets_total = 0
        self._t0 = 0.0
        self._nal_in_frame = 0
        self._frame_counter = 0
        self._last_out_pts: int | None = None
        self._last_frame_mono = 0.0
        self._nals_per_frame = 4

    def start_source(self, camera_extra_args: list[str] | None = None) -> None:
        if camera_extra_args is not None:
            self._camera_extra_args = camera_extra_args
        tool = _h264_tool_path()
        if not tool:
            raise RuntimeError("rpicam-vid / libcamera-vid not found")
        cmd = _build_rpicam_command(
            tool,
            self._width, self._height, self._fps,
            self._bitrate, self._intra, self._profile,
            self._camera_extra_args,
        )
        self._log_cmd(cmd)
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._started = True
        self._got_first_frame = False
        self._packets_total = 0
        self._t0 = time.monotonic()
        self._nal_in_frame = 0
        self._frame_counter = 0
        self._last_out_pts = None
        self._last_frame_mono = 0.0
        self._demux_thread = threading.Thread(
            target=self._demux_worker,
            daemon=True,
            name="h264-demux",
        )
        self._demux_thread.start()
        self._loop = asyncio.get_running_loop()
        self._reader_task = self._loop.create_task(self._reader_loop())

    def _demux_worker(self) -> None:
        proc = self._proc
        if not proc or not proc.stdout:
            self._packet_q.put(None)
            return
        try:
            container = av.open(proc.stdout, format="h264", mode="r")
            for packet in container.demux(video=0):
                if packet.size == 0:
                    continue
                self._packets_total += 1
                if self._packets_total <= 3 or self._packets_total % 300 == 0:
                    log.info(
                        "H264PassthroughTrack: packet #%d size=%d key=%s",
                        self._packets_total,
                        packet.size,
                        packet.is_keyframe,
                    )
                if self._nal_in_frame == 0:
                    self._frame_counter += 1
                packet.pts = self._frame_counter * self._pts_step
                self._nal_in_frame = (self._nal_in_frame + 1) % self._nals_per_frame
                packet.time_base = self._time_base
                try:
                    self._packet_q.put(packet, timeout=2.0)
                except queue.Full:
                    try:
                        self._packet_q.get_nowait()
                    except queue.Empty:
                        pass
                    self._packet_q.put(packet, timeout=2.0)
        except Exception:
            log.exception("H264PassthroughTrack: demux thread error")
        finally:
            self._packet_q.put(None)
            stderr_tail = ""
            if proc.stderr:
                try:
                    stderr_tail = proc.stderr.read(4096).decode(errors="replace")
                except Exception:
                    pass
            rc = proc.poll()
            log.info(
                "H264PassthroughTrack: demux done (packets=%d, rc=%s, stderr=%s)",
                self._packets_total,
                rc,
                stderr_tail[:500] if stderr_tail else "(empty)",
            )

    async def _reader_loop(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            while True:
                packet = await loop.run_in_executor(None, self._packet_q.get)
                if packet is None:
                    break
                if self._queue.full():
                    try:
                        self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                await self._queue.put(packet)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("H264PassthroughTrack: reader loop error")
        finally:
            log.info("H264PassthroughTrack: reader loop finished")

    async def recv(self) -> av.Packet:
        if self.readyState != "live":
            raise MediaStreamError
        if not self._started:
            self.start_source()
        deadline = (
            _FIRST_FRAME_RECV_TIMEOUT_SEC
            if not self._got_first_frame
            else _FRAME_RECV_TIMEOUT_SEC
        )
        try:
            packet = await asyncio.wait_for(self._queue.get(), timeout=deadline)
        except asyncio.TimeoutError:
            self._log_source_health(
                f"нет пакета за {deadline:.0f}s (до первого или между кадрами)"
            )
            raise MediaStreamError
        self._got_first_frame = True
        return packet

    async def restart_source(self, camera_extra_args: list[str] | None = None) -> None:
        log.info("H264PassthroughTrack: restarting source")
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._demux_thread and self._demux_thread.is_alive():
            self._demux_thread.join(timeout=3.0)
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        while not self._packet_q.empty():
            try:
                self._packet_q.get_nowait()
            except queue.Empty:
                break
        self._t0 = 0.0
        self.start_source(camera_extra_args)


class H264CameraTrack(_H264TrackBase):
    """
    Legacy: decodes H.264 to av.VideoFrame; aiortc libx264 re-encode (+0.5–1.5 s лага).
    """

    def __init__(
        self,
        width: int = 1280,
        height: int = 720,
        fps: float = 30.0,
        bitrate: int = 4_000_000,
        intra: int = 30,
        profile: str | None = "high",
        camera_extra_args: list[str] | None = None,
    ) -> None:
        super().__init__(
            width, height, fps, bitrate, intra, profile, camera_extra_args,
        )
        self._decode_thread: threading.Thread | None = None
        self._frame_q: queue.Queue[av.VideoFrame | None] = queue.Queue(
            maxsize=_DECODE_QUEUE_MAXSIZE,
        )
        self._queue: asyncio.Queue[av.VideoFrame] = asyncio.Queue(
            maxsize=_DECODE_QUEUE_MAXSIZE,
        )

    def start_source(self, camera_extra_args: list[str] | None = None) -> None:
        if camera_extra_args is not None:
            self._camera_extra_args = camera_extra_args
        tool = _h264_tool_path()
        if not tool:
            raise RuntimeError("rpicam-vid / libcamera-vid not found")
        cmd = _build_rpicam_command(
            tool,
            self._width, self._height, self._fps,
            self._bitrate, self._intra, self._profile,
            self._camera_extra_args,
        )
        self._log_cmd(cmd)
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._started = True
        self._got_first_frame = False
        self._decode_thread = threading.Thread(
            target=self._decoder_worker,
            daemon=True,
            name="h264-decoder",
        )
        self._decode_thread.start()
        self._loop = asyncio.get_running_loop()
        self._reader_task = self._loop.create_task(self._reader_loop())

    def _decoder_worker(self) -> None:
        """Thread: reads rpicam-vid pipe, decodes H.264 → av.VideoFrame, pushes to queue."""
        proc = self._proc
        if not proc or not proc.stdout:
            self._frame_q.put(None)
            return

        total_frames = 0
        try:
            container = av.open(proc.stdout, format="h264", mode="r")
            for frame in container.decode(video=0):
                total_frames += 1
                if total_frames <= 3 or total_frames % 200 == 0:
                    log.info("H264CameraTrack: decoded frame #%d %dx%d",
                             total_frames, frame.width, frame.height)
                try:
                    self._frame_q.put(frame, timeout=2.0)
                except queue.Full:
                    try:
                        self._frame_q.get_nowait()
                    except queue.Empty:
                        pass
                    self._frame_q.put(frame, timeout=2.0)
        except Exception:
            log.exception("H264CameraTrack: decoder thread error")
        finally:
            self._frame_q.put(None)
            stderr_tail = ""
            if proc.stderr:
                try:
                    stderr_tail = proc.stderr.read(4096).decode(errors="replace")
                except Exception:
                    pass
            rc = proc.poll()
            log.info("H264CameraTrack: decoder thread done (frames=%d, rc=%s, stderr=%s)",
                     total_frames, rc, stderr_tail[:500] if stderr_tail else "(empty)")

    async def _reader_loop(self) -> None:
        """Async bridge: pulls decoded VideoFrame from thread queue → asyncio queue."""
        loop = asyncio.get_event_loop()
        try:
            while True:
                frame = await loop.run_in_executor(None, self._frame_q.get)
                if frame is None:
                    break

                frame.pts = self._pts
                frame.time_base = self._time_base
                self._pts += self._pts_step

                if self._queue.full():
                    try:
                        self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                await self._queue.put(frame)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("H264CameraTrack: reader loop error")
        finally:
            log.info("H264CameraTrack: reader loop finished")

    async def recv(self) -> av.VideoFrame:
        if self.readyState != "live":
            raise MediaStreamError

        if not self._started:
            self.start_source()

        deadline = (
            _FIRST_FRAME_RECV_TIMEOUT_SEC
            if not self._got_first_frame
            else _FRAME_RECV_TIMEOUT_SEC
        )
        try:
            frame = await asyncio.wait_for(self._queue.get(), timeout=deadline)
        except asyncio.TimeoutError:
            self._log_source_health(
                f"нет кадра за {deadline:.0f}s (до первого или между кадрами)"
            )
            raise MediaStreamError
        self._got_first_frame = True
        return frame

    async def restart_source(self, camera_extra_args: list[str] | None = None) -> None:
        """Restart rpicam-vid with new camera args (preset/zoom change)."""
        log.info("H264CameraTrack: restarting source")
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()

        if self._decode_thread and self._decode_thread.is_alive():
            self._decode_thread.join(timeout=3.0)

        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        while not self._frame_q.empty():
            try:
                self._frame_q.get_nowait()
            except queue.Empty:
                break

        self._pts = 0
        self.start_source(camera_extra_args)
