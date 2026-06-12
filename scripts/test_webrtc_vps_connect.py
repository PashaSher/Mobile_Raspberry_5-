#!/usr/bin/env python3
"""Проверка VPS signaling: offer не стирается при пробуждении Pi (X-Clear: callee)."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "config" / "webrtc.vps.env"


def load_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if not ENV.is_file():
        raise SystemExit(f"нет {ENV}")
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def api(
    method: str,
    url: str,
    token: str,
    body: dict | None = None,
    *,
    extra_headers: dict[str, str] | None = None,
) -> dict | None:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} → HTTP {e.code}: {body_txt[:200]}") from e


def main() -> int:
    cfg = load_env()
    base = cfg["WEBRTC_SIGNAL_URL"].rstrip("/")
    room = cfg.get("WEBRTC_ROOM", "pi-camera")
    token = cfg["ICE_CONFIG_TOKEN"]
    room_url = f"{base}/rooms/{room}"

    print(f"[1] GET room {room_url}")
    state = api("GET", room_url, token) or {}
    print(f"    offer={'yes' if state.get('offer') else 'no'} host={state.get('host')}")

    fake_offer = {
        "type": "offer",
        "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n"
        "s=-\r\nt=0 0\r\na=ice-ufrag:testconnect\r\na=ice-pwd:testpwd\r\n"
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\na=recvonly\r\n",
    }
    print("[2] PUT fake offer (browser)")
    api("PUT", f"{room_url}/offer", token, fake_offer)

    state = api("GET", room_url, token) or {}
    assert state.get("offer"), "offer не записался"
    print("    OK offer on server")

    print("[3] DELETE X-Clear: callee (как Pi при launch)")
    api("DELETE", room_url, token, extra_headers={"X-Clear": "callee"})

    state = api("GET", room_url, token) or {}
    if not state.get("offer"):
        print("FAIL: offer стёрся после callee-clear")
        return 1
    print("    OK offer сохранён после callee-clear")

    print("[4] PUT host waking (как Pi)")
    api(
        "PUT",
        f"{room_url}/host",
        token,
        {
            "status": "waking",
            "powerSave": False,
            "needOffer": False,
            "hostLaunchId": int(time.time() * 1000),
        },
    )
    state = api("GET", room_url, token) or {}
    if not state.get("offer"):
        print("FAIL: offer пропал после host=waking")
        return 1
    print(f"    OK offer + host.status={state.get('host', {}).get('status')}")

    print("\nВсе проверки signaling пройдены.")
    print("На Pi: sudo systemctl restart camstream.service")
    print("В браузере: http://116.203.148.254/cam → Ctrl+Shift+R → Connect")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
