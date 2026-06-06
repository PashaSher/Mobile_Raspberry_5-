"""WebRTC Host на Raspberry Pi: peer connection, video track, Data Channel управления."""

from __future__ import annotations

import asyncio
import os
import json
import logging
import signal
import time
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from aiortc import RTCIceCandidate, RTCPeerConnection

    from rpi_tools.webrtc_video import H264CameraTrack

from rpi_tools.webrtc_vps_signaling import VpsSignaling, make_signaling

log = logging.getLogger("camstream.webrtc")

# Публичный STUN: помогает Windows/Chrome выдать нормальные srflx-кандидаты, не только 127.0.0.1.
STUN_SERVERS: list[str] = ["stun:stun.l.google.com:19302"]


def _pref_video_codec_preferences_for_answer() -> list:
    """Приоритет H.264 baseline (42001f) — чаще декодируется в Chrome/Edge без «тишины» на приёме."""
    from aiortc.codecs import get_capabilities

    caps = list(get_capabilities("video").codecs)

    def _pid(c):
        return (c.parameters or {}).get("profile-level-id", "")

    def _sort_key(c: object) -> tuple:
        p = _pid(c)
        if p == "42001f":
            tier = 0
        elif p == "42e01f":
            tier = 1
        else:
            tier = 2
        return (tier, p)

    h264_sorted = sorted(
        [c for c in caps if getattr(c, "mimeType", "") == "video/H264"],
        key=_sort_key,
    )
    vp8 = [c for c in caps if getattr(c, "name", "") == "VP8"]
    return [*h264_sorted, *vp8]


def _parse_ice_candidate(data: dict) -> RTCIceCandidate | None:
    """Разбор ICE из JSON браузера (Chrome/Firefox) для aiortc.addIceCandidate.

    Используем candidate_from_sdp из aiortc — корректнее ручного split() для части строк.
    """
    from aiortc.sdp import candidate_from_sdp

    raw = data.get("candidate", "")
    sdp_mid = data.get("sdpMid")
    sdp_mline_index = data.get("sdpMLineIndex")
    if not raw or raw == "":
        return None

    try:
        candidate = candidate_from_sdp(raw)
    except Exception as e:
        log.debug("ICE: разбор через candidate_from_sdp не удался (%s): %.120s…", e, raw)
        return None

    candidate.sdpMid = sdp_mid
    candidate.sdpMLineIndex = sdp_mline_index

    ip = candidate.ip or ""
    try:
        port = int(candidate.port)
    except (TypeError, ValueError):
        return None

    if ip.startswith("169.254."):
        log.debug("ICE: пропуск link-local кандидата %s:%s", ip, port)
        return None
    if port == 9:
        log.debug("ICE: пропуск порта 9 для %s", ip)
        return None

    return candidate


def _ice_candidates_from_sdp(sdp: str) -> list[dict]:
    """ICE из a=candidate: в SDP с sdpMid / sdpMLineIndex по секциям m=."""
    out: list[dict] = []
    mid = "0"
    mline_index = -1
    for line in (sdp or "").splitlines():
        line = line.strip()
        if line.startswith("m="):
            mline_index += 1
            mid = str(mline_index)
        elif line.startswith("a=mid:"):
            mid = line.split(":", 1)[1].strip()
        elif line.startswith("a=candidate:"):
            out.append({
                "candidate": line[2:],
                "sdpMid": mid,
                "sdpMLineIndex": max(0, mline_index),
            })
    return out


async def _publish_sdp_candidates_to_firebase(
    signaling: VpsSignaling,
    sdp: str,
    *,
    turn_only: bool = False,
) -> int:
    """Дублирует ICE из SDP в calleeCandidates (до answer — браузер видит relay сразу)."""
    n = 0
    for ent in _ice_candidates_from_sdp(sdp):
        cand = ent["candidate"]
        typ = _ice_typ_from_sdp(cand)
        if turn_only and typ != "relay":
            continue
        await signaling.send_ice_candidate(ent)
        n += 1
    if n:
        log.info(
            "WebRTC: SDP → VPS calleeCandidates: %d%s",
            n,
            " (только relay)" if turn_only else "",
        )
    elif turn_only:
        log.warning(
            "WebRTC: в SDP answer нет typ relay — Hetzner-only в браузере не подключится"
        )
    return n


def _ice_typ_from_sdp(sdp_line: str) -> str:
    """typ host|srflx|relay из SDP candidate line."""
    parts = (sdp_line or "").split()
    for i, part in enumerate(parts):
        if part == "typ" and i + 1 < len(parts):
            return parts[i + 1]
    return "?"


def _peer_media_ready(pc: RTCPeerConnection) -> bool:
    """Медиа уже идёт, хотя connectionState в aiortc может оставаться «connecting»."""
    if pc.connectionState == "connected":
        return True
    return pc.iceConnectionState in ("connected", "completed")


# После ice=disconnected ждём восстановления; дольше — завершаем сессию и ждём новый offer.
_ICE_DISCONNECT_GRACE_SEC = 4.0


async def _wait_ice_gathering_complete(pc: RTCPeerConnection, timeout_sec: float = 15.0) -> str:
    """Ждём relay/host кандидаты перед отправкой answer (важно для TURN-only в браузере)."""
    state = pc.iceGatheringState
    if state == "complete":
        return state

    done = asyncio.Event()

    @pc.on("icegatheringstatechange")
    async def _on_gather() -> None:
        if pc.iceGatheringState == "complete":
            done.set()

    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        log.warning(
            "WebRTC: ICE gathering не завершился за %.0f с (state=%s) — answer уйдёт с тем, что есть",
            timeout_sec,
            pc.iceGatheringState,
        )
    return pc.iceGatheringState


class WebRTCHost:
    """
    Main WebRTC host: creates peer connection, attaches H.264 video,
    handles Data Channel commands for Romeo and camera control.
    """

    def __init__(
        self,
        room_id: str,
        signal_url: str | None = None,
        ice_token: str | None = None,
        width: int = 1280,
        height: int = 720,
        fps: float = 30.0,
        bitrate: int = 4_000_000,
        intra: int = 30,
        profile: str | None = "baseline",
        camera_extra_args: list[str] | None = None,
        camera_args_provider: Callable[[], list[str]] | None = None,
        camera_state: object | None = None,
        command_handler: Callable[[dict], dict] | None = None,
        ice_config_url: str | None = None,
        ice_config_token: str | None = None,
        ice_merge_public_stun: bool = True,
        ice_fetch_timeout_sec: float = 8.0,
        ice_config_required: bool = False,
        ice_turn_only: bool = False,
        romeo_usb: str | None = None,
        romeo_baud: int = 115200,
        telemetry_interval_sec: float = 10.0,
        wifi_ifname: str | None = None,
    ) -> None:
        self._room_id = room_id
        self._signal_url = (signal_url or os.environ.get("WEBRTC_SIGNAL_URL", "")).strip() or None
        self._ice_token = ice_token or os.environ.get("ICE_CONFIG_TOKEN")
        self._command_handler = command_handler

        self._video_width = width
        self._video_height = height
        self._video_fps = fps
        self._video_bitrate = bitrate
        self._video_intra = intra
        self._video_profile = profile
        self._camera_extra_args = camera_extra_args
        self._camera_args_provider = camera_args_provider
        self._camera_state = camera_state
        self._async_loop: asyncio.AbstractEventLoop | None = None

        self._ice_config_url = (ice_config_url or "").strip() or None
        self._ice_config_token = ice_config_token if ice_config_token else None
        self._ice_merge_public_stun = ice_merge_public_stun
        self._ice_fetch_timeout_sec = ice_fetch_timeout_sec
        self._ice_config_required = ice_config_required
        self._ice_turn_only = ice_turn_only
        self._romeo_usb = (romeo_usb or "").strip() or None
        self._romeo_baud = int(romeo_baud)
        self._telemetry_interval_sec = max(0.0, float(telemetry_interval_sec))
        self._wifi_ifname = (wifi_ifname or "").strip() or None
        self._telemetry_task: asyncio.Task | None = None

        self._video_track: H264CameraTrack | None = None
        self._pc: RTCPeerConnection | None = None
        self._signaling: VpsSignaling | None = None
        self._running = False
        self._host_session_id = 0
        self._session_end: asyncio.Event | None = None
        self._disconnect_since: float | None = None

    def _request_session_end(self, reason: str) -> None:
        if self._session_end and not self._session_end.is_set():
            log.info("WebRTC: завершение сессии (%s)", reason)
            self._session_end.set()

    async def _await_session_end(self) -> None:
        """Держим сессию, пока браузер подключён; при Disconnect/обрыве — выходим."""
        if not self._pc or not self._session_end:
            return
        log.info(
            "WebRTC: streaming active — ждём Disconnect или новый offer с VPS (до %.0f с grace на disconnected)",
            _ICE_DISCONNECT_GRACE_SEC,
        )
        while self._running and self._pc and not self._session_end.is_set():
            pc = self._pc
            cs = pc.connectionState
            ice = pc.iceConnectionState
            if cs in ("failed", "closed") or ice in ("failed", "closed"):
                self._request_session_end(f"poll {cs}/{ice}")
                break
            if cs == "disconnected" or ice == "disconnected":
                now = time.monotonic()
                if self._disconnect_since is None:
                    self._disconnect_since = now
                elif now - self._disconnect_since >= _ICE_DISCONNECT_GRACE_SEC:
                    self._request_session_end(
                        f"disconnected >{_ICE_DISCONNECT_GRACE_SEC:.0f}s ({cs}/{ice})"
                    )
                    break
            else:
                self._disconnect_since = None
            try:
                await asyncio.wait_for(self._session_end.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass

    async def _finalize_session_for_reconnect(self) -> None:
        """VPS/Firebase: needOffer=true, очистка SDP — Pi снова в wait_for_offer."""
        if not self._signaling:
            return
        end = getattr(self._signaling, "end_session_for_reconnect", None)
        if callable(end):
            await end(self._host_session_id)
        else:
            await self._signaling.mark_failed_need_reconnect()
        self._prev_ufrag = None
        log.info(
            "WebRTC: готов к новому Connect (hostSessionId=%s, ждём offer на VPS)",
            self._host_session_id,
        )

    async def run(self) -> None:
        """Main loop: create room, wait for offer, connect, stream."""
        log.info(
            "WebRTC: signaling на VPS %s, комната %s",
            self._signal_url,
            self._room_id,
        )
        self._running = True
        self._async_loop = asyncio.get_running_loop()
        self._prev_ufrag: str | None = None
        self._signaling = make_signaling(
            self._room_id,
            signal_url=self._signal_url,
            ice_token=self._ice_token,
        )
        launch_id = int(time.time() * 1000)
        await self._signaling.reset_room_for_host_launch(launch_id)

        if self._telemetry_interval_sec > 0:
            self._telemetry_task = asyncio.create_task(
                self._telemetry_loop(),
                name="host-telemetry",
            )
            log.info(
                "WebRTC: телеметрия на VPS каждые %.1f с (батарея + Wi‑Fi)",
                self._telemetry_interval_sec,
            )

        try:
            while self._running:
                try:
                    await self._session()
                except asyncio.CancelledError:
                    break
                except Exception:
                    log.exception("WebRTC session error")
                finally:
                    await self._cleanup_session()

                if self._running:
                    self._host_session_id += 1
                    log.info(
                        "WebRTC: session ended, hostSessionId=%s — ждём offer на VPS (2s)",
                        self._host_session_id,
                    )
                    await asyncio.sleep(2.0)
        finally:
            if self._telemetry_task and not self._telemetry_task.done():
                self._telemetry_task.cancel()
                try:
                    await self._telemetry_task
                except asyncio.CancelledError:
                    pass
                self._telemetry_task = None

    async def _telemetry_loop(self) -> None:
        from rpi_tools.host_telemetry import build_host_telemetry_patch

        loop = asyncio.get_running_loop()
        while self._running:
            try:
                patch = await loop.run_in_executor(
                    None,
                    lambda: build_host_telemetry_patch(
                        romeo_port=self._romeo_usb,
                        romeo_baud=self._romeo_baud,
                        wifi_ifname=self._wifi_ifname,
                    ),
                )
                if self._signaling and hasattr(self._signaling, "push_host_telemetry"):
                    await self._signaling.push_host_telemetry(patch)
                    log.info(
                        "WebRTC: telemetry → VPS batteryV=%s wifi=%s%% %s",
                        patch.get("batteryV", "—"),
                        patch.get("wifiSignal", "—"),
                        patch.get("wifiSsid") or "",
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                log.debug("WebRTC: telemetry upload failed", exc_info=True)
            try:
                await asyncio.sleep(self._telemetry_interval_sec)
            except asyncio.CancelledError:
                break

    async def _session(self) -> None:
        if not self._signaling:
            self._signaling = make_signaling(
            self._room_id,
            signal_url=self._signal_url,
            ice_token=self._ice_token,
        )

        offer_data = await self._signaling.wait_for_offer(
            prev_ufrag=self._prev_ufrag,
            should_stop=lambda: not self._running,
        )
        self._prev_ufrag = self._signaling.last_ufrag

        from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription

        from rpi_tools.webrtc_ice_config import build_rtc_ice_servers
        from rpi_tools.webrtc_video import H264CameraTrack

        ice_servers = await build_rtc_ice_servers(
            ice_config_url=self._ice_config_url,
            ice_config_token=self._ice_config_token,
            fallback_stun_urls=STUN_SERVERS,
            merge_public_stun=self._ice_merge_public_stun,
            fetch_timeout_sec=self._ice_fetch_timeout_sec,
            ice_config_required=self._ice_config_required,
            ice_turn_only=self._ice_turn_only,
        )
        config = RTCConfiguration(iceServers=ice_servers)
        self._pc = RTCPeerConnection(configuration=config)
        self._session_end = asyncio.Event()
        self._disconnect_since = None
        log.info("WebRTC: peer connection created")

        v_tx = self._pc.addTransceiver("video", direction="sendrecv")
        try:
            prefs = _pref_video_codec_preferences_for_answer()
            if prefs:
                v_tx.setCodecPreferences(prefs)
                log.info(
                    "WebRTC: setCodecPreferences до setRemote (H264 profile-level-id): %s",
                    [
                        (c.parameters or {}).get("profile-level-id", "?")
                        for c in prefs
                        if getattr(c, "mimeType", "") == "video/H264"
                    ]
                    or "?",
                )
        except Exception as exc:
            log.warning("WebRTC: setCodecPreferences (video): %s", exc)

        def _wire_data_channel(channel) -> None:
            @channel.on("open")
            def on_open():
                log.info("WebRTC: Data Channel %r открыт (готов к JSON-командам)", channel.label)

            @channel.on("message")
            def on_msg(msg):
                self._handle_data_channel_message(channel, msg)

        @self._pc.on("datachannel")
        def on_datachannel(channel):
            log.info("WebRTC: Data Channel от клиента label=%r", channel.label)
            _wire_data_channel(channel)

        @self._pc.on("connectionstatechange")
        async def on_connection_state_change():
            state = self._pc.connectionState
            ice = self._pc.iceConnectionState
            log.info("WebRTC: connection state -> %s (ice=%s)", state, ice)
            if state == "connected":
                await self._signaling.set_status("connected")
            elif state in ("failed", "closed", "disconnected"):
                self._request_session_end(f"connection={state} (ice={ice})")

        @self._pc.on("iceconnectionstatechange")
        async def on_ice_state():
            ice = self._pc.iceConnectionState
            log.info("WebRTC: ICE state -> %s", ice)
            if ice in ("failed", "closed"):
                self._request_session_end(f"ice={ice}")

        local_ice_typs: list[str] = []

        @self._pc.on("icecandidate")
        async def on_ice_candidate(candidate):
            if candidate and self._signaling:
                sdp_line = candidate.to_sdp()
                typ = _ice_typ_from_sdp(sdp_line)
                local_ice_typs.append(typ)
                if self._ice_turn_only and typ != "relay":
                    log.debug(
                        "WebRTC: skip ICE typ=%s (режим VPS-only)",
                        typ,
                    )
                    return
                log.info(
                    "WebRTC: local ICE typ=%s -> VPS calleeCandidates (%.80s…)",
                    typ,
                    sdp_line,
                )
                await self._signaling.send_ice_candidate({
                    "candidate": sdp_line,
                    "sdpMid": candidate.sdpMid,
                    "sdpMLineIndex": candidate.sdpMLineIndex,
                })

        offer = RTCSessionDescription(
            sdp=offer_data["sdp"],
            type=offer_data.get("type", "offer"),
        )
        await self._pc.setRemoteDescription(offer)
        log.info("WebRTC: remote description set")

        # В offer нет m=application — браузер не поднял SCTP; создаём канал с Pi (часть старых страниц).
        offer_sdp = offer_data.get("sdp", "")
        if "m=application" not in offer_sdp.lower():
            try:
                dc_pi = self._pc.createDataChannel("romeo", ordered=True)
                _wire_data_channel(dc_pi)
                log.info(
                    "WebRTC: в SDP не было SCTP — создан исходящий DataChannel %r со стороны Pi",
                    dc_pi.label,
                )
            except Exception as ex:
                log.warning("WebRTC: не удалось создать DataChannel на Pi: %s", ex)

        seen_candidates: set[str] = set()

        async def _safe_add_remote_ice(candidate: RTCIceCandidate) -> None:
            if not self._pc:
                return
            try:
                await self._pc.addIceCandidate(candidate)
            except Exception as ex:
                log.warning(
                    "WebRTC: addIceCandidate remote %s:%s failed: %s",
                    candidate.ip,
                    candidate.port,
                    ex,
                )

        def _add_candidate(candidate_data: dict) -> None:
            key = candidate_data.get("candidate", "")
            if not key or key in seen_candidates:
                return
            seen_candidates.add(key)
            candidate = _parse_ice_candidate(candidate_data)
            if candidate and self._pc:
                raw = candidate_data.get("candidate", "")
                log.info(
                    "WebRTC: remote ICE typ=%s %s:%s (callerCandidates)",
                    _ice_typ_from_sdp(raw),
                    candidate.ip,
                    candidate.port,
                )
                asyncio.ensure_future(_safe_add_remote_ice(candidate))

        existing = await self._signaling.poll_remote_candidates()
        for c_data in existing:
            _add_candidate(c_data)
        if existing:
            log.info("WebRTC: loaded %d existing ICE candidates", len(existing))

        self._signaling.listen_remote_candidates(_add_candidate)

        from rpi_tools.camera_stream import kill_stale_rpicam_processes

        kill_stale_rpicam_processes()
        cam_args = self._current_camera_args()
        log.warning(
            "WebRTC: rpicam camera args для этой сессии: %s",
            " ".join(cam_args or []) or "(libcamera defaults)",
        )
        self._video_track = H264CameraTrack(
            width=self._video_width,
            height=self._video_height,
            fps=self._video_fps,
            bitrate=self._video_bitrate,
            intra=self._video_intra,
            profile=self._video_profile,
            camera_extra_args=cam_args,
        )
        try:
            self._video_track.start_source(cam_args)
            self._mark_camera_args_applied(cam_args)
            log.info(
                "WebRTC: rpicam/камера запущены до SDP answer (быстрее первый RTP)"
            )
        except Exception as ex:
            log.error(
                "WebRTC: не удалось запустить камеру до answer: %s. "
                "Проверьте rpicam-vid / libcamera-vid и доступ к камере.",
                ex,
            )
            raise

        v_tx.sender.replaceTrack(self._video_track)
        log.info(
            "WebRTC: H.264-трек привязан к трансоверу (replaceTrack) перед createAnswer"
        )

        answer = await self._pc.createAnswer()
        await self._pc.setLocalDescription(answer)
        gather_state = await _wait_ice_gathering_complete(self._pc, timeout_sec=15.0)
        relay_n = sum(1 for t in local_ice_typs if t == "relay")
        log.info(
            "WebRTC: ICE gathering=%s, локальных кандидатов=%d (relay=%d) — typ: %s",
            gather_state,
            len(local_ice_typs),
            relay_n,
            local_ice_typs[:12] if local_ice_typs else "нет (TURN с Pi не отдался?)",
        )
        if relay_n == 0 and local_ice_typs:
            log.warning(
                "WebRTC: нет typ relay с Pi — при iceTransportPolicy=relay в браузере "
                "сессия оборвётся. Запуск с --ice-vps-only и проверьте coturn/UDP 49160-65535 на VPS."
            )
        log.info("WebRTC: local description set (answer)")
        try:
            for t in self._pc.getTransceivers():
                if t.kind != "video" or not getattr(t.sender, "track", None):
                    continue
                cdx = getattr(t, "_codecs", None) or ()
                names = []
                for c in cdx[:6]:
                    n = getattr(c, "name", None) or str(c)
                    names.append(n)
                log.info(
                    "WebRTC: видеотрансовер направление=%s согласованные кодеки: %s",
                    getattr(t, "direction", "?"),
                    names or "?",
                )
        except Exception as ex:
            log.debug("WebRTC: лог кодеков: %s", ex)

        answer_sdp = self._pc.localDescription.sdp
        await _publish_sdp_candidates_to_firebase(
            self._signaling,
            answer_sdp,
            turn_only=self._ice_turn_only,
        )
        await self._signaling.send_answer({
            "sdp": answer_sdp,
            "type": self._pc.localDescription.type,
        })

        async def _poll_and_signal_eoc() -> None:
            """Poll for late candidates, then signal end-of-candidates."""
            for _ in range(20):
                await asyncio.sleep(1.0)
                if not self._pc or _peer_media_ready(self._pc):
                    return
                candidates = await self._signaling.poll_remote_candidates()
                for c_data in candidates:
                    _add_candidate(c_data)

            if self._pc and not _peer_media_ready(self._pc):
                log.info("WebRTC: signaling end-of-candidates")
                try:
                    await self._pc.addIceCandidate(None)
                except Exception:
                    log.debug("WebRTC: addIceCandidate(None) not supported, skipping")

        poll_task = asyncio.ensure_future(_poll_and_signal_eoc())

        deadline = asyncio.get_event_loop().time() + 60.0
        while self._running and self._pc:
            pc = self._pc
            if pc.connectionState in ("failed", "closed"):
                log.info("WebRTC: connection %s — ending session", pc.connectionState)
                break
            if pc.iceConnectionState in ("failed", "closed"):
                log.info("WebRTC: ICE %s — ending session", pc.iceConnectionState)
                break
            if _peer_media_ready(pc):
                log.info(
                    "WebRTC: media path up (connection=%s ice=%s)",
                    pc.connectionState,
                    pc.iceConnectionState,
                )
                break
            if asyncio.get_event_loop().time() > deadline:
                log.warning(
                    "WebRTC: connect timeout (60s, connection=%s ice=%s) — ending session",
                    pc.connectionState,
                    pc.iceConnectionState,
                )
                break
            await asyncio.sleep(0.3)

        poll_task.cancel()

        if self._pc and _peer_media_ready(self._pc):
            await self._await_session_end()

    def _handle_data_channel_message(self, channel, message: str | bytes) -> None:
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")

        text = message.strip()
        if not text:
            return

        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = {"romeo": text}

        response: dict
        if self._command_handler:
            try:
                response = self._command_handler(obj) or {
                    "ok": False,
                    "error": "no handler for command",
                }
            except Exception as e:
                response = {"ok": False, "error": str(e)}
        else:
            response = {"ok": False, "error": "no command handler configured"}

        if (
            isinstance(response, dict)
            and response.get("changed")
            and str(response.get("camera_action", "")).startswith("camera_")
            and self._video_track
            and self._camera_args_provider
            and self._async_loop
        ):
            cam_args = self._current_camera_args()
            asyncio.run_coroutine_threadsafe(
                self._restart_rpicam_with_args(cam_args),
                self._async_loop,
            )
            log.info(
                "WebRTC: rpicam перезапуск после %s, args=%s",
                response.get("camera_action"),
                " ".join(cam_args),
            )

        if channel and channel.readyState == "open":
            try:
                channel.send(json.dumps(response, ensure_ascii=False))
            except Exception:
                log.debug("WebRTC: failed to send DC response")

    async def _cleanup_session(self) -> None:
        try:
            await self._finalize_session_for_reconnect()
        except Exception:
            log.warning("WebRTC: finalize session failed", exc_info=True)
        self._session_end = None
        self._disconnect_since = None
        if self._video_track:
            self._video_track.stop()
            self._video_track = None
        self._kill_stale_rpicam()
        if self._pc:
            try:
                await self._pc.close()
            except Exception:
                pass
            self._pc = None
        if self._signaling:
            try:
                await self._signaling.cleanup()
            except Exception:
                pass

    @staticmethod
    def _kill_stale_rpicam() -> None:
        from rpi_tools.camera_stream import kill_stale_rpicam_processes

        kill_stale_rpicam_processes()

    def request_stop(self) -> None:
        self._running = False

    def _current_camera_args(self) -> list[str] | None:
        if self._camera_args_provider:
            return self._camera_args_provider()
        return self._camera_extra_args

    def _mark_camera_args_applied(self, cam_args: list[str] | None) -> None:
        if cam_args is None or self._camera_state is None:
            return
        mark = getattr(self._camera_state, "mark_rpicam_applied", None)
        if callable(mark):
            mark(cam_args)

    async def _restart_rpicam_with_args(self, cam_args: list[str] | None) -> None:
        if not self._video_track:
            return
        await self._video_track.restart_source(cam_args)
        self._mark_camera_args_applied(cam_args or [])


async def run_webrtc_host(
    room_id: str,
    signal_url: str | None = None,
    ice_token: str | None = None,
    width: int = 1280,
    height: int = 720,
    fps: float = 30.0,
    bitrate: int = 4_000_000,
    intra: int = 30,
    profile: str | None = "baseline",
    camera_extra_args: list[str] | None = None,
    camera_args_provider: Callable[[], list[str]] | None = None,
    camera_state: object | None = None,
    command_handler: Callable[[dict], dict] | None = None,
    ice_config_url: str | None = None,
    ice_config_token: str | None = None,
    ice_merge_public_stun: bool = True,
    ice_fetch_timeout_sec: float = 8.0,
    ice_config_required: bool = False,
    ice_turn_only: bool = False,
    romeo_usb: str | None = None,
    romeo_baud: int = 115200,
    telemetry_interval_sec: float = 10.0,
    wifi_ifname: str | None = None,
) -> None:
    """Entry point: run WebRTC host until interrupted."""
    try:
        import aiortc as _aiortc  # noqa: F401
        import av as _av  # noqa: F401
        del _aiortc, _av
    except ModuleNotFoundError as e:
        log.error(
            "Не установлен пакет aiortc (обычно вместе с PyAV/av). "
            "В этом же интерпретаторе: pip install aiortc av или pip install -r requirements.txt "
            "(см. %s).",
            e,
        )
        raise SystemExit(1) from e

    host = WebRTCHost(
        room_id=room_id,
        signal_url=signal_url,
        ice_token=ice_token,
        width=width, height=height, fps=fps,
        bitrate=bitrate, intra=intra, profile=profile,
        camera_extra_args=camera_extra_args,
        camera_args_provider=camera_args_provider,
        camera_state=camera_state,
        command_handler=command_handler,
        ice_config_url=ice_config_url,
        ice_config_token=ice_config_token,
        ice_merge_public_stun=ice_merge_public_stun,
        ice_fetch_timeout_sec=ice_fetch_timeout_sec,
        ice_config_required=ice_config_required,
        ice_turn_only=ice_turn_only,
        romeo_usb=romeo_usb,
        romeo_baud=romeo_baud,
        telemetry_interval_sec=telemetry_interval_sec,
        wifi_ifname=wifi_ifname,
    )

    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _signal_handler():
        log.info("WebRTC: stop signal received")
        host.request_stop()
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    run_task = asyncio.create_task(host.run())
    stop_wait = asyncio.create_task(stop_event.wait())
    try:
        done, pending = await asyncio.wait(
            {run_task, stop_wait},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        if stop_wait in done and not run_task.done():
            host.request_stop()
            run_task.cancel()
            try:
                await run_task
            except asyncio.CancelledError:
                pass
        elif run_task in done:
            await run_task
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.remove_signal_handler(sig)
            except NotImplementedError:
                pass
