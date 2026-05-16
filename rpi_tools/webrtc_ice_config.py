"""Загрузка ICE (STUN/TURN) с HTTP API для WebRTC вне домашней сети (coturn + ice_config_server)."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

log = logging.getLogger("camstream.webrtc")


def _ice_url_with_token_param(url: str, token: str) -> str:
    if "token=" in url:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode({"token": token})


def _fetch_ice_json_sync(url: str, token: str | None, timeout_sec: float) -> dict[str, Any]:
    """GET JSON с телом вида {\"iceServers\": [...] }."""
    final_url = url
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        final_url = _ice_url_with_token_param(url, token)

    req = Request(final_url, headers=headers, method="GET")
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=timeout_sec, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def ice_json_to_rtci_servers(entries: list[Any]) -> list:
    """Преобразует массив WebRTC iceServers в список aiortc.RTCIceServer."""
    from aiortc import RTCIceServer

    out: list[RTCIceServer] = []
    for ent in entries:
        if not isinstance(ent, dict):
            continue
        urls = ent.get("urls")
        if urls is None:
            continue
        kwargs: dict[str, Any] = {"urls": urls}
        u = ent.get("username")
        if u is not None and u != "":
            kwargs["username"] = str(u)
        c = ent.get("credential")
        if c is not None:
            kwargs["credential"] = str(c)
        ct = ent.get("credentialType")
        if ct:
            kwargs["credentialType"] = str(ct)
        out.append(RTCIceServer(**kwargs))
    return out


def filter_turn_only_ice_servers(servers: list) -> list:
    """Оставить только TURN (relay через VPS); убрать STUN из ответа ICE API."""
    out: list = []
    for s in servers:
        raw = getattr(s, "urls", None)
        if raw is None:
            continue
        urls = [raw] if isinstance(raw, str) else list(raw)
        if any(str(u).strip().lower().startswith("turn:") for u in urls):
            out.append(s)
    return out


async def load_ice_servers_from_http(
    url: str,
    token: str | None,
    *,
    timeout_sec: float = 8.0,
) -> list:
    """
    Асинхронная обёртка: HTTP GET в thread pool, парс iceServers → RTCIceServer.
    При ошибке бросает исключение (вызывающий решает fallback).
    """
    data = await asyncio.to_thread(_fetch_ice_json_sync, url, token, timeout_sec)
    servers = data.get("iceServers")
    if not isinstance(servers, list):
        raise ValueError("ответ API: ожидался массив iceServers")
    return ice_json_to_rtci_servers(servers)


async def build_rtc_ice_servers(
    *,
    ice_config_url: str | None,
    ice_config_token: str | None,
    fallback_stun_urls: list[str],
    merge_public_stun: bool,
    fetch_timeout_sec: float = 8.0,
    ice_config_required: bool = False,
    ice_turn_only: bool = False,
) -> list:
    """
    Собирает список RTCIceServer для RTCConfiguration.

    - Если задан ice_config_url: GET JSON, iceServers; при успехе + опционально
      дописывает fallback_stun_urls (Google STUN и т.д.).
    - Если URL не задан или запрос/парсинг не удались — только fallback_stun_urls,
      кроме ice_config_required (тогда ошибка).
    - ice_turn_only: только turn: из ответа API (режим «только relay через VPS»).
    """
    from aiortc import RTCIceServer

    fallback = [RTCIceServer(urls=u) for u in fallback_stun_urls if u]

    if not (ice_config_url and ice_config_url.strip()):
        if ice_config_required:
            raise RuntimeError(
                "WebRTC: задан режим только VPS (ICE API обязателен), но --ice-config-url / ICE_CONFIG_URL пуст"
            )
        log.info("WebRTC: ICE API не задан — только встроенный STUN (%s)", fallback_stun_urls)
        return fallback

    u = ice_config_url.strip()
    try:
        remote = await load_ice_servers_from_http(
            u, ice_config_token, timeout_sec=fetch_timeout_sec
        )
    except HTTPError as e:
        if ice_config_required:
            raise RuntimeError(
                f"WebRTC: ICE API HTTP {e.code} {e.reason} — режим VPS-only без fallback"
            ) from e
        log.warning("WebRTC: ICE API HTTP %s: %s — fallback STUN", e.code, e.reason)
        return fallback
    except (URLError, OSError, TimeoutError, json.JSONDecodeError, ValueError) as e:
        if ice_config_required:
            raise RuntimeError(
                f"WebRTC: ICE API недоступен ({e}) — режим VPS-only без fallback"
            ) from e
        log.warning("WebRTC: ICE API недоступен (%s) — fallback STUN", e)
        return fallback

    if not remote:
        if ice_config_required:
            raise RuntimeError("WebRTC: ICE API вернул пустой iceServers — режим VPS-only")
        log.warning("WebRTC: ICE API вернул пустой iceServers — fallback STUN")
        return fallback

    if ice_turn_only:
        remote = filter_turn_only_ice_servers(remote)
        if not remote:
            raise RuntimeError(
                "WebRTC: в ответе ICE API нет turn: — режим VPS-only (relay) невозможен"
            )
        log.info("WebRTC: ICE только TURN с VPS (%d серверов)", len(remote))
        return remote

    if merge_public_stun and fallback:
        merged = list(remote)
        merged.extend(fallback)
        log.info(
            "WebRTC: ICE из API (%d серверов) + публичный STUN (%d)",
            len(remote),
            len(fallback),
        )
        return merged

    log.info("WebRTC: ICE только из API (%d серверов)", len(remote))
    return remote
