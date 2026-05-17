#!/usr/bin/env bash
# WebRTC на Pi: signaling через VPS (config/webrtc.vps.env), без Firebase.
#
#   ./scripts/camstream_webrtc.sh
#   ./scripts/camstream_webrtc.sh -v
#   ./scripts/camstream_webrtc.sh --room-only
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${CAMSTREAM_PYTHON:-${ROOT}/.venv/bin/python}"
SCRIPT="${STREAM_CAMERA_SCRIPT:-${ROOT}/stream_camera.py}"
ENV="${ROOT}/config/webrtc.vps.env"

# Два юнита (webrtc-vps.service + camstream.service) → два stream_camera, обрыв каждые ~30 с.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet webrtc-vps.service 2>/dev/null; then
    echo "camstream_webrtc: отключите webrtc-vps.service: sudo systemctl disable --now webrtc-vps.service" >&2
    exit 3
  fi
fi

if [[ ! -f "${ENV}" ]]; then
  echo "camstream_webrtc: нет ${ENV}" >&2
  echo "  cp config/webrtc.vps.env.example config/webrtc.vps.env  # и подставьте ICE_CONFIG_TOKEN" >&2
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

# Как в launch.json «RPI: debug (webrtc)»: -v перед подкомандой webrtc.
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

exec "${PY}" "${SCRIPT}" "${args[@]}"
