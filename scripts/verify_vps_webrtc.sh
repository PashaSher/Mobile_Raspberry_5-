#!/usr/bin/env bash
# Проверка VPS: ICE + signaling (без Pi).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV="${ROOT}/config/webrtc.vps.env"
if [[ ! -f "${ENV}" ]]; then
  echo "нет ${ENV}" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090
source "${ENV}"
set +a

ok=0
fail=0
check() {
  local name="$1"
  shift
  if "$@"; then
    echo "OK  ${name}"
    ok=$((ok + 1))
  else
    echo "FAIL ${name}"
    fail=$((fail + 1))
  fi
}

check "ping VPS" ping -c 1 -W 3 116.203.148.254 >/dev/null 2>&1

check "ICE API" curl -sf -m 8 -H "Authorization: Bearer ${ICE_CONFIG_TOKEN}" "${ICE_CONFIG_URL}" \
  | grep -q 'turn:116.203.148.254'

EV_URL="${WEBRTC_SIGNAL_URL}/rooms/${WEBRTC_ROOM:-pi-camera}/events?since=0&timeout=2"
check "signaling events" curl -sf -m 10 -H "Authorization: Bearer ${ICE_CONFIG_TOKEN}" "${EV_URL}" \
  | grep -q '"status"'

check "operator /cam" curl -sf -m 8 -o /dev/null -w '' "http://116.203.148.254/cam" \
  || curl -sf -m 8 -o /dev/null -w '' -L "http://116.203.148.254/cam"

echo "--- ${ok} ok, ${fail} fail ---"
exit "$([[ ${fail} -eq 0 ]] && echo 0 || echo 1)"
