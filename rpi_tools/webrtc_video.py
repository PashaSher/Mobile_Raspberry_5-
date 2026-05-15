"""H.264 camera track for WebRTC: rpicam-vid → decode → av.VideoFrame for aiortc."""

from __future__ import annotations

import asyncio
import fractions
import logging
import queue
import shutil
import subprocess
import threading
from typing import Optional

import av
from aiortc import MediaStreamTrack
from aiortc.mediastreams import MediaStreamError

log = logging.getLogger("camstream.webrtc")

# Размер очередей декодирования → aiortc. Раньше 30 кадров @ 30 fps давали до ~1 с задержки
# между реальностью и тем, что читает RTP (плюс браузер). Маленькая очередь: меньше лаг,
# возможны дропы кадров при всплесках нагрузки.
_DECODE_QUEUE_MAXSIZE = 3

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
        "--flush",
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


class H264CameraTrack(MediaStreamTrack):
    """
    Reads H.264 from rpicam-vid, decodes to av.VideoFrame,
    and yields frames for aiortc's RTP sender to re-encode.
    """

    kind = "video"

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
        super().__init__()
        self._width = width
        self._height = height
        self._fps = fps
        self._bitrate = bitrate
        self._intra = intra
        self._profile = profile
        self._camera_extra_args = camera_extra_args or []

        self._proc: subprocess.Popen | None = None
        self._decode_thread: threading.Thread | None = None
        self._frame_q: queue.Queue[av.VideoFrame | None] = queue.Queue(
            maxsize=_DECODE_QUEUE_MAXSIZE,
        )
        self._queue: asyncio.Queue[av.VideoFrame] = asyncio.Queue(
            maxsize=_DECODE_QUEUE_MAXSIZE,
        )
        self._reader_task: asyncio.Task | None = None
        self._started = False
        self._got_first_frame = False
        self._pts = 0
        self._time_base = fractions.Fraction(1, 90000)
        self._pts_step = int(90000 / max(1, fps))
        self._loop: asyncio.AbstractEventLoop | None = None

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
        log.info("H264CameraTrack: starting %s", " ".join(cmd))
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

    def _log_source_health(self, context: str) -> None:
        """При отсутствии кадров — понять: rpicam умер или ещё крутится."""
        proc = self._proc
        if not proc:
            log.warning("H264CameraTrack: %s — нет процесса камеры", context)
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
                "H264CameraTrack: %s — rpicam/libcamera завершился rc=%s stderr=%s",
                context,
                rc,
                (tail[:1200] if tail else "(пусто)"),
            )
        else:
            log.warning(
                "H264CameraTrack: %s — процесс жив, кадров в очереди пока нет",
                context,
            )

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
            log.info("H264CameraTrack: rpicam-vid stopped")

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
