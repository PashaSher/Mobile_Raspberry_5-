"""WebRTC signaling via VPS HTTP API (replaces Firebase RTDB)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable

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

    async def reset_room_for_host_launch(self, launch_id: int) -> None:
        def _go() -> None:
            patch = {
                "needOffer": True,
                "hostLaunchId": launch_id,
                "hostSessionId": 0,
                "status": "waiting",
            }
            self._http.set_host(patch)
            self._http.clear_room(timeout_sec=3.0)

        await self._run_sync(_go)
        log.info(
            "VPS: room %r — Pi start (hostLaunchId=%s), needOffer=true",
            self._room_id,
            launch_id,
        )

    async def reset_room_for_retry(self, session_id: int) -> None:
        def _go() -> None:
            self._http.set_host({
                "needOffer": True,
                "hostSessionId": session_id,
                "status": "waiting",
            })

        await self._run_sync(_go)
        log.info("VPS: room %r — retry cycle %s, needOffer=true", self._room_id, session_id)

    async def create_room(self, *, clear_offer: bool = True) -> None:
        await self.reset_room_for_host_launch(int(time.time() * 1000))

    async def wait_for_offer(
        self,
        prev_ufrag: str | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> dict:
        def _poll_once() -> dict | None:
            try:
                ev = self._http.wait_events(timeout=20.0)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                log.debug("VPS: wait_events (no offer yet): %s", e)
                return None
            offer = self._coerce_offer(ev.get("offer"))
            if not offer:
                return None
            ufrag = self._extract_ufrag(offer.get("sdp", ""))
            if prev_ufrag and ufrag == prev_ufrag:
                return None
            return offer

        log.info("VPS: waiting for offer on room %s", self._room_id)
        while True:
            if should_stop and should_stop():
                raise asyncio.CancelledError("VPS: stop while waiting for offer")
            offer = await self._run_sync(_poll_once)
            if offer:
                self._last_ufrag = self._extract_ufrag(offer.get("sdp", ""))
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
        await self._run_sync(
            lambda: self._http.set_host({"status": "waiting", "needOffer": True})
        )
        log.info("VPS: session failed — needOffer=true, status=waiting")

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
        def _go() -> list[dict]:
            try:
                ev = self._http.wait_events(timeout=2.0)
            except (urllib.error.URLError, TimeoutError, OSError):
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

        return await self._run_sync(_go)

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
