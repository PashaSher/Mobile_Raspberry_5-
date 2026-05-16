#!/usr/bin/env bash
# Собирает config/camstream.debug.env для VS Code/Cursor (один envFile, без ${env:…} в launch.json).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FB="${ROOT}/config/firebase.debug.env"
ICE="${ROOT}/config/webrtc.ice.local.env"
OUT="${ROOT}/config/camstream.debug.env"

"${ROOT}/scripts/ensure_firebase_debug_env.sh"
"${ROOT}/scripts/ensure_webrtc_ice_env.sh"

: >"${OUT}"
if [[ -f "${FB}" ]]; then
  grep -v '^[[:space:]]*#' "${FB}" | grep -v '^[[:space:]]*$' >>"${OUT}" || true
fi
if [[ -f "${ICE}" ]]; then
  grep -v '^[[:space:]]*#' "${ICE}" | grep -v '^[[:space:]]*$' >>"${OUT}" || true
fi
chmod 600 "${OUT}" 2>/dev/null || true

if [[ ! -s "${OUT}" ]]; then
  echo "[merge_camstream_debug_env] пустой ${OUT} — нужны firebase.debug.env и webrtc.ice.local.env" >&2
  exit 1
fi
