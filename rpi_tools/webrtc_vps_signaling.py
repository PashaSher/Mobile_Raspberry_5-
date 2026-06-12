"""WebRTC signaling via VPS HTTP API (replaces Firebase RTDB)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Awaitable, Callable

log = logging.getLogger("camstream.webrtc")


def normalize_room(room: str) -> str:
    r = (room or "").strip().strip("/")
    if r.startswith("rooms/"):
        r = r[6:]
    return r or "pi-camera"


class _VpsHttp:
    def __init__(self, api_base: str, room: str, ice_token: str) -> None:
        self.api_base = api_base.rstrip("/")
        self.room = normalize_room(room)
        self.ice_token = (ice_token or "").strip()
        self._since = 0

    def _headers(self, *, auth: bool = False) -> dict[str, str]:
        hdrs = {"Content-Type": "application/json"}
        if auth and self.ice_token:
            hdrs["Authorization"] = f"Bearer {self.ice_token}"
        return hdrs

    def _url(self, *parts: str) -> str:
        tail = "/".join(parts)
        return f"{self.api_base}/rooms/{self.room}" + (f"/{tail}" if tail else "")

    def _request(
        self,
        method: str,
        path_parts: tuple[str, ...] = (),
        body: dict | None = None,
        *,
        auth: bool = False,
        timeout_sec: float = 10.0,
    ) -> Any:
        url = self._url(*path_parts)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(auth=auth), method=method)
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))

    def clear_room(self, *, timeout_sec: float = 3.0) -> bool:
        try:
            self._request("DELETE", (), auth=True, timeout_sec=timeout_sec)
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("VPS: DELETE room %s — %s (продолжаем)", self.room, e)
            return False


    def clear_caller_side(self, *, timeout_sec: float = 3.0) -> bool:
        """Сбросить offer и ICE браузера (X-Clear: caller)."""
        url = self._url()
        hdrs = self._headers(auth=True)
        hdrs["X-Clear"] = "caller"
        req = urllib.request.Request(url, headers=hdrs, method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                resp.read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("VPS: DELETE caller %s — %s (продолжаем)", self.room, e)
            return False

    def clear_callee_side(self, *, timeout_sec: float = 3.0) -> bool:
        """Сбросить только answer/ICE Pi (X-Clear: callee), не трогая offer браузера."""
        url = self._url()
        hdrs = self._headers(auth=True)
        hdrs["X-Clear"] = "callee"
        req = urllib.request.Request(url, headers=hdrs, method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                resp.read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("VPS: DELETE callee %s — %s (продолжаем)", self.room, e)
            return False

    def fetch_room(self) -> dict[str, Any] | None:
        try:
            return self._request("GET", (), auth=True)
        except (urllib.error.URLError, TimeoutError, OSError):
            return None

    def wait_events(self, timeout: float = 8.0) -> dict[str, Any]:
        url = (
            f"{self._url('events')}?since={self._since}"
            f"&timeout={max(1, min(int(timeout), 30))}"
        )
        req = urllib.request.Request(url, method="GET", headers=self._headers(auth=True))
        http_wait = max(timeout + 12.0, 20.0)
        with urllib.request.urlopen(req, timeout=http_wait) as resp:
            ev = json.loads(resp.read().decode("utf-8"))
        self._since = int(ev.get("seq", self._since))
        return ev

    def set_host(self, patch: dict[str, Any], *, retries: int = 5) -> None:
        last: BaseException | None = None
        for attempt in range(1, retries + 1):
            try:
                self._request("PUT", ("host",), patch, auth=True, timeout_sec=8.0)
                return
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
                log.warning("VPS: PUT host %d/%d: %s", attempt, retries, e)
                time.sleep(min(1.5 * attempt, 5.0))
        raise RuntimeError(f"VPS PUT /host failed after {retries} tries") from last

    def put_answer(self, answer: dict[str, Any]) -> None:
        self._request("PUT", ("answer",), answer, auth=True)

    def post_callee_candidate(self, cand: dict[str, Any]) -> None:
        self._request("POST", ("callee-candidates",), cand, auth=True)


class VpsSignaling:
    """Async API compatible with FirebaseSignaling for webrtc_host."""

    def __init__(self, room_id: str, api_base: str | None = None, ice_token: str | None = None) -> None:
        self._room_id = normalize_room(room_id)
        base = (api_base or os.environ.get("WEBRTC_SIGNAL_URL", "")).strip()
        token = ice_token if ice_token is not None else os.environ.get("ICE_CONFIG_TOKEN", "")
        if not base:
            raise RuntimeError("WEBRTC_SIGNAL_URL is not set")
        self._http = _VpsHttp(base, self._room_id, token)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._poll_task: asyncio.Task | None = None
        self._remote_cb: Callable[[dict], None] | None = None
        self._seen_caller: set[str] = set()
        self._last_ufrag: str | None = None
        self._events_handler: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    def set_events_handler(
        self,
        handler: Callable[[dict[str, Any]], Awaitable[None]] | None,
    ) -> None:
        """Колбэк на каждый ответ /events (telemetryPing, connectIntent, …)."""
        self._events_handler = handler

    async def _dispatch_events(self, ev: dict[str, Any]) -> None:
        if not self._events_handler:
            return
        try:
            await self._events_handler(ev)
        except Exception:
            log.debug("VPS: events handler failed", exc_info=True)

    @staticmethod
    def telemetry_ping_from_events(ev: dict[str, Any]) -> int | None:
        """Сервер шлёт host.telemetryPing — Pi отвечает PUT телеметрией."""
        for src in (ev.get("host"), ev):
            if not isinstance(src, dict):
                continue
            ping = src.get("telemetryPing")
            if ping is None:
                continue
            try:
                return int(ping)
            except (TypeError, ValueError):
                continue
        return None

    async def _wait_events_async(self, timeout: float) -> dict[str, Any] | None:
        try:
            ev = await self._run_sync(lambda: self._http.wait_events(timeout=timeout))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.debug("VPS: wait_events: %s", e)
            return None
        if isinstance(ev, dict):
            await self._dispatch_events(ev)
            return ev
        return None

    @property
    def room_id(self) -> str:
        return self._room_id

    @property
    def last_ufrag(self) -> str | None:
        return self._last_ufrag

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_event_loop()
        self._loop = loop
        return loop

    def _run_sync(self, fn):
        loop = self._bind_loop()
        return loop.run_in_executor(None, fn)

    @staticmethod
    def _extract_ufrag(sdp: str) -> str | None:
        for line in sdp.splitlines():
            if line.startswith("a=ice-ufrag:"):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _coerce_offer(data: Any) -> dict | None:
        if data is None:
            return None
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return None
        if isinstance(data, dict) and data.get("sdp"):
            return data
        return None

    @staticmethod
    def _is_plausible_browser_offer(sdp: str) -> tuple[bool, str]:
        """Отсекаем monitor/test fake SDP до setRemoteDescription (aiortc требует rtcp-mux)."""
        low = (sdp or "").lower()
        ufrag = (VpsSignaling._extract_ufrag(sdp) or "").lower()
        if ufrag in ("testconnect", "test"):
            return False, f"bogus ufrag={ufrag!r}"
        if "a=rtcp-mux" not in low:
            return False, "нет a=rtcp-mux"
        if "m=video" not in low and "m=application" not in low:
            return False, "нет m=video / m=application"
        return True, ""

    async def reset_room_for_host_launch(self, launch_id: int) -> None:
        def _go() -> None:
            patch = {
                "needOffer": True,
                "hostLaunchId": launch_id,
                "hostSessionId": 0,
                "status": "waiting",
                "powerSave": True,
            }
            self._http.set_host(patch)
            self._http.clear_callee_side(timeout_sec=3.0)

        await self._run_sync(_go)
        log.info(
            "VPS: room %r — Pi start (hostLaunchId=%s), callee cleared (offer сохранён)",
            self._room_id,
            launch_id,
        )

    async def reset_room_for_retry(self, session_id: int) -> None:
        def _go() -> None:
            self._http.set_host({
                "needOffer": False,
                "hostSessionId": session_id,
                "status": "waiting",
            })

        await self._run_sync(_go)
        log.info(
            "VPS: room %r — retry cycle %s, needOffer=false (ручной Connect)",
            self._room_id,
            session_id,
        )

    async def create_room(self, *, clear_offer: bool = True) -> None:
        await self.reset_room_for_host_launch(int(time.time() * 1000))

    @staticmethod
    def _connect_intent_from_events(ev: dict[str, Any]) -> bool:
        """Ранний ping Connect до SDP offer (если VPS/браузер шлёт connectIntent)."""
        intent = ev.get("connectIntent")
        if intent is True or intent == 1:
            return True
        host = ev.get("host") or {}
        if isinstance(host, dict) and host.get("connectIntent"):
            return True
        return False

    async def peek_new_browser_offer(self, current_ufrag: str | None) -> bool:
        def _go() -> bool:
            snap = self._http.fetch_room() or {}
            offer = self._coerce_offer(snap.get("offer"))
            if not offer:
                return False
            ufrag = self._extract_ufrag(offer.get("sdp", ""))
            if not ufrag or ufrag == (current_ufrag or ""):
                return False
            ok, _ = self._is_plausible_browser_offer(offer.get("sdp", ""))
            return ok

        return bool(await self._run_sync(_go))

    async def wait_for_offer(
        self,
        prev_ufrag: str | None = None,
        should_stop: Callable[[], bool] | None = None,
        *,
        power_idle: bool = False,
    ) -> dict:
        async def _poll_once() -> dict | None:
            ev = await self._wait_events_async(25.0 if power_idle else 20.0)
            if not ev:
                return None
            if power_idle and self._connect_intent_from_events(ev):
                log.info("VPS: connectIntent ping — ждём SDP offer")
            offer = self._coerce_offer(ev.get("offer"))
            if not offer:
                return None
            ufrag = self._extract_ufrag(offer.get("sdp", ""))
            if prev_ufrag and ufrag == prev_ufrag:
                return None
            return offer

        if power_idle:
            log.info(
                "VPS: режим экономии — long-poll (offer + telemetryPing) на room %s",
                self._room_id,
            )
        else:
            log.info("VPS: waiting for offer on room %s", self._room_id)
        while True:
            if should_stop and should_stop():
                raise asyncio.CancelledError("VPS: stop while waiting for offer")
            offer = await _poll_once()
            if offer:
                ufrag = self._extract_ufrag(offer.get("sdp", ""))
                ok, why = self._is_plausible_browser_offer(offer.get("sdp", ""))
                if not ok:
                    log.warning(
                        "VPS: пропуск offer (ufrag=%s): %s — ждём настоящий Connect",
                        ufrag,
                        why,
                    )
                    if power_idle:
                        await self.ensure_power_listen()
                    continue
                self._last_ufrag = ufrag
                log.info(
                    "VPS: received offer (type=%s, ufrag=%s)",
                    offer.get("type", "?"),
                    self._last_ufrag,
                )
                return offer

    async def send_answer(self, answer: dict) -> None:
        def _go() -> None:
            self._http.put_answer(answer)
            self._http.set_host({"status": "negotiating", "needOffer": False})

        await self._run_sync(_go)
        log.info("VPS: answer sent (status=negotiating, needOffer=false)")

    async def mark_failed_need_reconnect(self) -> None:
        await self.end_session_for_reconnect(session_id=None)

    async def end_session_for_reconnect(
        self,
        session_id: int | None = None,
        *,
        power_idle: bool = False,
    ) -> None:
        """После Disconnect/обрыва: очистить SDP/ICE; needOffer=false — без авто-Connect в браузере."""

        def _go() -> None:
            self._http.clear_callee_side(timeout_sec=3.0)
            self._http.clear_caller_side(timeout_sec=3.0)
            patch: dict[str, Any] = {
                "needOffer": True,
                "status": "waiting",
            }
            if power_idle:
                patch["powerSave"] = True
            else:
                patch["powerSave"] = False
            if session_id is not None:
                patch["hostSessionId"] = session_id
            self._http.set_host(patch, retries=3)

        self._seen_caller.clear()
        self._last_ufrag = None
        self._http._since = 0
        await self._run_sync(_go)
        sid = f", hostSessionId={session_id}" if session_id is not None else ""
        if power_idle:
            log.info(
                "VPS: session ended — waiting/powerSave, needOffer=true%s (ждём Connect в браузере)",
                sid,
            )
        else:
            log.info(
                "VPS: session ended — waiting, needOffer=true%s (ждём Connect в браузере)",
                sid,
            )

    async def enter_power_idle(self, session_id: int) -> None:
        await self.end_session_for_reconnect(session_id, power_idle=True)

    async def ensure_power_listen(self) -> None:
        """Сигнал на VPS: Pi слушает комнату (камера выкл), ждём Connect."""

        def _go() -> None:
            self._http.set_host(
                {"status": "waiting", "needOffer": True, "powerSave": True},
                retries=1,
            )

        await self._run_sync(_go)

    async def enter_power_active(self) -> None:
        def _go() -> None:
            self._http.set_host({"status": "waking", "powerSave": False}, retries=2)

        await self._run_sync(_go)
        log.info("VPS: ping (offer) — пробуждение, status=waking")

    async def send_ice_candidate(self, candidate: dict) -> None:
        await self._run_sync(lambda: self._http.post_callee_candidate(candidate))

    def listen_remote_candidates(self, callback: Callable[[dict], None]) -> None:
        self._remote_cb = callback
        if self._poll_task and not self._poll_task.done():
            return
        self._poll_task = asyncio.ensure_future(self._poll_remote_loop())

    async def _poll_remote_loop(self) -> None:
        while self._remote_cb is not None:
            try:
                for c in await self.poll_remote_candidates():
                    if self._remote_cb:
                        self._remote_cb(c)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("VPS: poll callerCandidates: %s", e)
            await asyncio.sleep(0.4)

    async def poll_remote_candidates(self) -> list[dict]:
        ev = await self._wait_events_async(2.0)
        if not ev:
            return []
        bag = ev.get("callerCandidates") or {}
        out: list[dict] = []
        for cid, raw in bag.items():
            if cid in self._seen_caller:
                continue
            if isinstance(raw, dict) and raw.get("candidate"):
                self._seen_caller.add(cid)
                out.append(raw)
        return out

    async def set_status(self, status: str) -> None:
        await self._run_sync(lambda: self._http.set_host({"status": status}))

    async def push_host_telemetry(self, patch: dict[str, Any]) -> None:
        """Обновить host телеметрией (батарея, Wi‑Fi); merge на стороне VPS."""
        if not patch:
            return

        def _go() -> None:
            self._http.set_host(patch, retries=2)

        await self._run_sync(_go)

    async def cleanup(self) -> None:
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        self._remote_cb = None
        log.info("VPS: polling stopped for room %r", self._room_id)


def make_signaling(
    room_id: str,
    *,
    signal_url: str | None = None,
    ice_token: str | None = None,
) -> VpsSignaling:
    return VpsSignaling(room_id, api_base=signal_url, ice_token=ice_token)
