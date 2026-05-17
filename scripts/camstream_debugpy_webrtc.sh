#!/usr/bin/env bash
# debugpy + WebRTC: те же config/webrtc.vps.env и аргументы, что «RPI: debug (webrtc)».
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV="${ROOT}/config/webrtc.vps.env"

if [[ ! -f "${ENV}" ]]; then
  echo "camstream_debugpy_webrtc: нет ${ENV}" >&2
  echo "  cp config/webrtc.vps.env.example config/webrtc.vps.env" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "${ENV}"
set +a

: "${WEBRTC_SIGNAL_URL:?WEBRTC_SIGNAL_URL не задан в ${ENV}}"
: "${ICE_CONFIG_URL:?ICE_CONFIG_URL не задан}"
: "${ICE_CONFIG_TOKEN:?ICE_CONFIG_TOKEN не задан}"

ROOM="${WEBRTC_ROOM:-pi-camera}"

extra=()
want_v=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) want_v=1; shift ;;
    --room-only) extra+=(--room-only); shift ;;
    *) extra+=("$1"); shift ;;
  esac
done

args=()
(( want_v )) && args+=(-v)
args+=(webrtc --room "${ROOM}" --ice-vps-only "${extra[@]}")

exec "${ROOT}/scripts/camstream_debugpy_listen.sh" "${args[@]}"
