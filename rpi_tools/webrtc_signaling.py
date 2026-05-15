"""Firebase Realtime Database signaling для WebRTC на Raspberry Pi."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Callable

import firebase_admin
from firebase_admin import credentials, db as rtdb

log = logging.getLogger("camstream.webrtc")

_app_initialized = False
_app_lock = threading.Lock()


def init_firebase(cred_path: str, database_url: str) -> None:
    """Initialize Firebase Admin SDK (idempotent).

    Если приложение уже инициализировано другим модулем, повторная инициализация не
    выполняется; при несовпадении databaseURL пишется предупреждение.
    """
    global _app_initialized
    with _app_lock:
        if _app_initialized:
            try:
                app = firebase_admin.get_app()
                existing = (app.options or {}).get("databaseURL")
                if existing and existing.rstrip("/") != database_url.rstrip("/"):
                    log.warning(
                        "Firebase: приложение уже с databaseURL=%s; запрошен %s — "
                        "запись пойдёт в первый URL. Перезапустите процесс с одним URL.",
                        existing,
                        database_url,
                    )
            except ValueError:
                pass
            return
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred, {"databaseURL": database_url})
        _app_initialized = True
        log.info("Firebase: initialized (db=%s)", database_url)


class FirebaseSignaling:
    """
    WebRTC signaling through Firebase Realtime Database.

    DB structure::

        /rooms/{room_id}/
            offer        — SDP offer (JSON string, written by client)
            answer       — SDP answer (JSON string, written by Pi)
            callerCandidates / calleeCandidates — ICE (имена для совместимости с клиентом)
            status       — "waiting" | "connected" | "closed"
    """

    def __init__(self, room_id: str) -> None:
        self._room_id = room_id
        self._base_ref = rtdb.reference(f"/rooms/{room_id}")
        self._listeners: list[Any] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def room_id(self) -> str:
        return self._room_id

    async def create_room(self, *, clear_offer: bool = True) -> None:
        """Сброс сессии signaling: answer и ICE-кандидаты; status=waiting.

        Раньше здесь был полный delete(/rooms/<id>/), из‑за чего пропадал offer браузера:
        клиент один раз пишет offer, Pi стирал узел и ждал новый — ответ не уходил никогда.

        clear_offer:
            True — стереть и offer (новый цикл после прошлого ufrag на этом хосте).
            False — не трогать offer (первый заход: offer клиента уже может лежать в RTDB).
        """
        loop = asyncio.get_event_loop()
        self._loop = loop

        def _reset() -> None:
            base = self._base_ref
            for name in ("answer", "calleeCandidates", "callerCandidates"):
                try:
                    base.child(name).delete()
                except Exception as e:
                    log.debug(
                        "Firebase: room %r child %s delete: %s",
                        self._room_id,
                        name,
                        e,
                    )
            if clear_offer:
                try:
                    base.child("offer").delete()
                except Exception as e:
                    log.debug(
                        "Firebase: room %r offer delete: %s",
                        self._room_id,
                        e,
                    )
            st = base.child("status")
            st.set("waiting")
            snapshot = st.get()
            if snapshot != "waiting":
                raise RuntimeError(
                    f"RTDB после set статус всё равно {snapshot!r}; путь={st.path}"
                )

        try:
            await loop.run_in_executor(None, _reset)
        except Exception:
            log.exception(
                "Firebase: не удалось записать комнату %r (cred, --firebase-db-url, "
                "включена ли именно Realtime Database?)",
                self._room_id,
            )
            raise

        path = self._base_ref.path
        log.info(
            "Firebase: комната %r готова (%s/status=waiting, clear_offer=%s).",
            self._room_id,
            path,
            clear_offer,
        )

    async def wait_for_offer(self, prev_ufrag: str | None = None) -> dict:
        """Получить SDP offer: сначала уже лежащий в RTDB, иначе слушать изменения."""
        loop = asyncio.get_event_loop()
        offer_ref = self._base_ref.child("offer")

        def _extract_ufrag(sdp: str) -> str | None:
            for line in sdp.splitlines():
                if line.startswith("a=ice-ufrag:"):
                    return line.split(":", 1)[1].strip()
            return None

        def _coerce_offer(data: Any) -> dict | None:
            if data is None:
                return None
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    return None
            if not isinstance(data, dict) or "sdp" not in data:
                return None
            return data

        snap = await loop.run_in_executor(None, offer_ref.get)
        existing = _coerce_offer(snap)
        if existing:
            ufrag0 = _extract_ufrag(existing.get("sdp", ""))
            if not (prev_ufrag and ufrag0 == prev_ufrag):
                self._last_ufrag = ufrag0
                log.info(
                    "Firebase: offer уже в RTDB (type=%s, ufrag=%s)",
                    existing.get("type", "?"),
                    ufrag0,
                )
                return existing

        offer_future: asyncio.Future[dict] = loop.create_future()

        def _on_offer(event: Any) -> None:
            data = event.data
            coerced = _coerce_offer(data)
            if not coerced:
                return
            ufrag = _extract_ufrag(coerced.get("sdp", ""))
            if prev_ufrag and ufrag == prev_ufrag:
                return
            if not offer_future.done():
                loop.call_soon_threadsafe(offer_future.set_result, coerced)

        listener = offer_ref.listen(_on_offer)
        self._listeners.append(listener)

        log.info("Firebase: listening for offer on /rooms/%s/offer", self._room_id)
        offer = await offer_future
        listener.close()
        self._listeners.remove(listener)

        ufrag = _extract_ufrag(offer.get("sdp", ""))
        log.info(
            "Firebase: received offer (type=%s, ufrag=%s)",
            offer.get("type", "?"),
            ufrag,
        )
        self._last_ufrag = ufrag
        return offer

    @property
    def last_ufrag(self) -> str | None:
        return getattr(self, "_last_ufrag", None)

    async def send_answer(self, answer: dict) -> None:
        """Write SDP answer to Firebase as a plain dict (not JSON string)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._base_ref.child("answer").set, answer
        )
        log.info("Firebase: answer sent")

    async def send_ice_candidate(self, candidate: dict) -> None:
        """Push a local ICE candidate to Firebase (calleeCandidates for compatibility)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._base_ref.child("calleeCandidates").push, candidate
        )

    def listen_remote_candidates(
        self, callback: Callable[[dict], None]
    ) -> None:
        """Start listening for remote ICE candidates from the client (callerCandidates)."""
        loop = self._loop or asyncio.get_event_loop()

        def _dispatch(data: Any) -> None:
            if data is None:
                return
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    return
            if isinstance(data, dict):
                if "candidate" in data:
                    log.debug("Firebase: got ICE candidate (listener)")
                    loop.call_soon_threadsafe(callback, data)
                else:
                    for v in data.values():
                        if isinstance(v, dict) and "candidate" in v:
                            log.debug("Firebase: got ICE candidate (listener/bulk)")
                            loop.call_soon_threadsafe(callback, v)

        def _on_candidate(event: Any) -> None:
            log.debug("Firebase: callerCandidates event path=%s data_type=%s",
                       getattr(event, 'path', '?'), type(event.data).__name__)
            _dispatch(event.data)

        ref = self._base_ref.child("callerCandidates")
        listener = ref.listen(_on_candidate)
        self._listeners.append(listener)
        log.info("Firebase: listening for remote ICE candidates (callerCandidates)")

    async def poll_remote_candidates(self) -> list[dict]:
        """Directly read callerCandidates from Firebase (fallback for listener)."""
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(
            None, self._base_ref.child("callerCandidates").get
        )
        if not data or not isinstance(data, dict):
            return []
        candidates = []
        for v in data.values():
            if isinstance(v, dict) and "candidate" in v:
                candidates.append(v)
        return candidates

    async def set_status(self, status: str) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._base_ref.child("status").set, status
        )

    async def cleanup(self) -> None:
        """Close listeners with a timeout to avoid blocking."""
        loop = asyncio.get_event_loop()

        def _close_all() -> None:
            for listener in self._listeners:
                try:
                    listener.close()
                except Exception:
                    pass
            self._listeners.clear()

        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, _close_all),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            log.warning("Firebase: listener cleanup timed out (5s)")
            self._listeners.clear()
        log.info("Firebase: listeners for room '%s' closed", self._room_id)
