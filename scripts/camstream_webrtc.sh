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

args=(webrtc --room "${ROOM}" --ice-vps-only)
if [[ "${1:-}" == "--room-only" ]]; then
  args+=(--room-only)
  shift
fi

exec "${PY}" "${SCRIPT}" "${args[@]}" "$@"
