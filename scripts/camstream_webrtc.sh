#!/usr/bin/env bash
# Запуск stream_camera.py webrtc из config/firebase.debug.env + config/webrtc.ice.local.env.
#
#   ./scripts/camstream_webrtc.sh
#   ./scripts/camstream_webrtc.sh -v
#   ./scripts/camstream_webrtc.sh --room-only   # проверка Firebase без камеры
#
# На Pi после копирования с VPS (show-ice-client-env.sh):
#   config/webrtc.ice.local.env  (ICE_CONFIG_URL, ICE_CONFIG_TOKEN)
#   config/firebase.debug.env    (CAMSTREAM_FIREBASE_*)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${CAMSTREAM_PYTHON:-${ROOT}/.venv/bin/python}"
SCRIPT="${STREAM_CAMERA_SCRIPT:-${ROOT}/stream_camera.py}"

_firebase_env="${ROOT}/config/firebase.debug.env"
_ice_env="${ROOT}/config/webrtc.ice.local.env"

if [[ -f "${_firebase_env}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${_firebase_env}"
  set +a
else
  echo "camstream_webrtc: нет ${_firebase_env}" >&2
  echo "  cp config/firebase.debug.env.example config/firebase.debug.env" >&2
  echo "  положите ключ *-firebase-adminsdk-*.json в корень проекта (см. .gitignore)" >&2
  exit 2
fi

if [[ -f "${_ice_env}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${_ice_env}"
  set +a
else
  echo "camstream_webrtc: нет ${_ice_env} — WebRTC вне LAN без TURN не заработает." >&2
  echo "  на VPS: sudo …/scripts/show-ice-client-env.sh → скопировать в config/webrtc.ice.local.env" >&2
  exit 2
fi

: "${CAMSTREAM_FIREBASE_CRED:?CAMSTREAM_FIREBASE_CRED не задан в config/firebase.debug.env}"
: "${CAMSTREAM_FIREBASE_DB_URL:?CAMSTREAM_FIREBASE_DB_URL не задан}"

CRED="${CAMSTREAM_FIREBASE_CRED}"
if [[ "${CRED}" != /* ]]; then
  CRED="${ROOT}/${CRED}"
fi
if [[ ! -f "${CRED}" ]]; then
  echo "camstream_webrtc: ключ Firebase не найден: ${CRED}" >&2
  exit 2
fi

ROOM="${CAMSTREAM_WEBRTC_ROOM:-pi-camera}"
ICE_URL="${ICE_CONFIG_URL:-}"
ICE_TOKEN="${ICE_CONFIG_TOKEN:-}"

if [[ -z "${ICE_URL}" ]] || [[ -z "${ICE_TOKEN}" ]]; then
  echo "camstream_webrtc: задайте ICE_CONFIG_URL и ICE_CONFIG_TOKEN в ${_ice_env}" >&2
  exit 2
fi

args=(
  webrtc
  --firebase-cred "${CRED}"
  --firebase-db-url "${CAMSTREAM_FIREBASE_DB_URL}"
  --room "${ROOM}"
  --ice-config-url "${ICE_URL}"
  --ice-config-token "${ICE_TOKEN}"
)

exec "${PY}" "${SCRIPT}" "${args[@]}" "$@"
