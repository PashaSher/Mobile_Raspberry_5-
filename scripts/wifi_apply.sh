#!/usr/bin/env bash
# Подключение к Wi‑Fi по сохранённому конфигу (NetworkManager, autoconnect).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -n "${1:-}" ]]; then
  exec python3 stream_camera.py wifi-apply --env-file "$1"
fi
exec python3 stream_camera.py wifi-apply
