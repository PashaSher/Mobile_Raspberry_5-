#!/usr/bin/env bash
# Сборка и выкладка страницы оператора с duplex audio на VPS.
#
#   VPS_HOST=116.203.148.254 VPS_USER=root ./scripts/deploy_vps_cam_audio.sh
#   VPS_CAM_PATH=/var/www/cam/index.html  # путь на сервере, уточните у себя
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VPS_HOST="${VPS_HOST:-116.203.148.254}"
VPS_USER="${VPS_USER:-root}"
VPS_CAM_PATH="${VPS_CAM_PATH:-}"

PATCHED="${ROOT}/deploy/vps/webrtc-client_with_audio.html"

python3 "${ROOT}/scripts/patch_operator_cam_audio.py"

if [[ -z "${VPS_CAM_PATH}" ]]; then
  echo "[deploy_vps_cam_audio] Патч готов: ${PATCHED}"
  echo "Задайте VPS_CAM_PATH и повторите для scp, например:"
  echo "  VPS_CAM_PATH=/var/www/html/webrtc-client.html $0"
  exit 0
fi

REMOTE="${VPS_USER}@${VPS_HOST}:${VPS_CAM_PATH}"
echo "[deploy_vps_cam_audio] ${PATCHED} → ${REMOTE}"
scp "${PATCHED}" "${REMOTE}"
echo "[deploy_vps_cam_audio] готово. Обновите http://${VPS_HOST}/cam или /webrtc-client.html (Ctrl+Shift+R)"
