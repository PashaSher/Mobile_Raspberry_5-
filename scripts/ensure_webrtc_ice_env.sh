#!/usr/bin/env bash
# Создаёт config/webrtc.ice.local.env из примера, если файла ещё нет.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE="${ROOT}/config/webrtc.ice.env.example"
TARGET="${ROOT}/config/webrtc.ice.local.env"
if [[ ! -f "${EXAMPLE}" ]]; then
  echo "[ensure_webrtc_ice_env] нет файла: ${EXAMPLE}" >&2
  exit 0
fi
if [[ ! -f "${TARGET}" ]]; then
  cp "${EXAMPLE}" "${TARGET}"
  chmod 600 "${TARGET}" 2>/dev/null || true
  echo "[ensure_webrtc_ice_env] создан ${TARGET}" >&2
  echo "  подставьте токен с VPS: sudo …/scripts/show-ice-client-env.sh" >&2
fi
exit 0
