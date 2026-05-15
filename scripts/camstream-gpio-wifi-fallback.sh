#!/usr/bin/env bash
# Обёртка для systemd: boot_gpio_gate → exec на приложение (stream_camera или debugpy-оболочку).
# Hotspot только если среди аргументов приложения есть --ap-ssid (внутри stream_camera).
# Если gate не запустил приложение — маркер от boot_gpio_gate → nmcli connection up CAMSTREAM_HOME_WIFI_CONN.
#
# Режимы:
#   camstream-gpio-wifi-fallback.sh send --video-mode udp_h264 --host 192.168.1.16 --port 5000 --stream-preset realtime
#   camstream-gpio-wifi-fallback.sh --wrapper /path/camstream_debugpy_listen.sh -- send --video-mode udp_h264 --host 192.168.1.16 --port 5000 --stream-preset realtime
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_GATE="${CAMSTREAM_BOOT_PYTHON:-/usr/bin/python3}"
PY_APP="${CAMSTREAM_PYTHON:-${ROOT}/.venv/bin/python}"
SCRIPT="${STREAM_CAMERA_SCRIPT:-${ROOT}/stream_camera.py}"
MARKER="${CAMSTREAM_GATE_SKIP_MARKER:-/tmp/camstream-gpio-no-launch.${UID:-$(id -u)}}"

TARGET=()
if [[ "${1:-}" == "--wrapper" ]]; then
  shift
  WR="${1:?укажите путь после --wrapper}"
  shift
  if [[ "${1:-}" != "--" ]]; then
    echo "camstream-gpio-wifi-fallback: после пути к wrapper ожидается --" >&2
    exit 2
  fi
  shift
  TARGET=("$WR" "$@")
else
  if [[ $# -lt 1 ]]; then
    echo "camstream-gpio-wifi-fallback: нужны аргументы для stream_camera (например: send --video-mode udp_h264 --host 192.168.1.16 …)" >&2
    exit 2
  fi
  TARGET=("$PY_APP" "$SCRIPT" "$@")
fi

rm -f -- "$MARKER"

"$PY_GATE" -m rpi_tools.boot_gpio_gate \
  --stable-ms "${BOOT_GPIO_STABLE_MS:-400}" \
  --wait-ground-sec "${BOOT_GPIO_WAIT_GROUND_SEC:-60}" \
  -- \
  "${TARGET[@]}"
ec=$?

if [[ -f "$MARKER" ]] && [[ -n "${CAMSTREAM_HOME_WIFI_CONN:-}" ]]; then
  rm -f -- "$MARKER"
  echo "camstream-gpio-wifi-fallback: приложение не запущено (GPIO gate) — nmcli connection up ${CAMSTREAM_HOME_WIFI_CONN}" >&2
  nmcli -w 45 connection up "$CAMSTREAM_HOME_WIFI_CONN" >&2 || true
elif [[ -f "$MARKER" ]]; then
  rm -f -- "$MARKER"
fi

exit "$ec"
