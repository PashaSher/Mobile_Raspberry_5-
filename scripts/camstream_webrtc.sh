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

# WiFi power_save → пропуски UDP → ICE «Consent expired» и обрыв через 10–30 с.
_wifi_ps_off() {
  local wif="$1"
  iw dev "$wif" info >/dev/null 2>&1 || return 0
  if iw dev "$wif" set power_save off 2>/dev/null; then
    echo "[camstream_webrtc] ${wif}: power_save off" >&2
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n iw dev "$wif" set power_save off 2>/dev/null; then
    echo "[camstream_webrtc] ${wif}: power_save off (sudo)" >&2
    return 0
  fi
  echo "[camstream_webrtc] ${wif}: power_save не выключен (нужен sudo iw … set power_save off)" >&2
}
if command -v iw >/dev/null 2>&1; then
  for wif in wlan0 wlan1; do
    _wifi_ps_off "$wif"
  done
fi

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
args+=(webrtc --room "${ROOM}")
# relay-only через VPS (по умолчанию). CAMSTREAM_ICE_VPS_ONLY=0 — STUN/P2P, если оператор с ?p2p=1 в одной сети.
if [[ "${CAMSTREAM_ICE_VPS_ONLY:-1}" != "0" ]]; then
  args+=(--ice-vps-only)
fi
args+=("${extra[@]}")
if [[ -n "${CAMSTREAM_VIDEO_BITRATE:-}" ]]; then
  args+=(--video-bitrate "${CAMSTREAM_VIDEO_BITRATE}")
fi
if [[ -n "${CAMSTREAM_VIDEO_FPS:-}" ]]; then
  args+=(--fps "${CAMSTREAM_VIDEO_FPS}")
fi
if [[ -n "${CAMSTREAM_VIDEO_WIDTH:-}" ]]; then
  args+=(--width "${CAMSTREAM_VIDEO_WIDTH}")
fi
if [[ -n "${CAMSTREAM_VIDEO_HEIGHT:-}" ]]; then
  args+=(--height "${CAMSTREAM_VIDEO_HEIGHT}")
fi
if [[ -n "${CAMSTREAM_VIDEO_INTRA:-}" ]]; then
  args+=(--video-intra "${CAMSTREAM_VIDEO_INTRA}")
fi
if [[ "${WEBRTC_AUDIO:-1}" == "0" ]]; then
  args+=(--no-audio)
else
  if [[ "${WEBRTC_AUDIO_PLAYBACK:-1}" == "0" ]]; then
    args+=(--no-audio-playback)
  fi
fi

exec "${PY}" "${SCRIPT}" "${args[@]}"
