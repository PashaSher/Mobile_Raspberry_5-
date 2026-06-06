#!/usr/bin/env bash
# Подготовка Raspberry Pi перед WebRTC (VPS): config, один процесс, сброс комнаты, запуск.
#
#   ./scripts/pi_camstream_bootstrap.sh              # проверка + room reset + systemd/nohup
#   ./scripts/pi_camstream_bootstrap.sh --check-only # только проверки
#   ./scripts/pi_camstream_bootstrap.sh --foreground # без systemd, camstream_webrtc.sh -v на переднем плане
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV="${ROOT}/config/webrtc.vps.env"
ENV_EXAMPLE="${ROOT}/config/webrtc.vps.env.example"
PY="${CAMSTREAM_PYTHON:-${ROOT}/.venv/bin/python}"
LOG="${CAMSTREAM_BOOT_LOG:-/tmp/camstream_webrtc.log}"

CHECK_ONLY=0
NO_START=0
FOREGROUND=0
SKIP_ROOM_RESET=0

usage() {
  sed -n '2,7p' "$0" | sed 's/^# \?//'
  echo "Опции: --check-only --no-start --foreground --skip-room-reset -h"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --foreground) FOREGROUND=1; shift ;;
    --skip-room-reset) SKIP_ROOM_RESET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "pi_camstream_bootstrap: неизвестный аргумент: $1" >&2; usage; exit 2 ;;
  esac
done

say() { echo "[pi_camstream_bootstrap] $*" >&2; }

ensure_webrtc_env() {
  if [[ ! -f "${ENV}" ]]; then
    if [[ ! -f "${ENV_EXAMPLE}" ]]; then
      say "нет ${ENV} и ${ENV_EXAMPLE}"
      exit 2
    fi
    cp "${ENV_EXAMPLE}" "${ENV}"
    chmod 600 "${ENV}" 2>/dev/null || true
    say "создан ${ENV} — вставьте ICE_CONFIG_TOKEN с VPS"
  fi
  # shellcheck disable=SC1090
  set -a
  source "${ENV}"
  set +a
  : "${WEBRTC_SIGNAL_URL:?WEBRTC_SIGNAL_URL не задан в ${ENV}}"
  : "${ICE_CONFIG_URL:?ICE_CONFIG_URL не задан}"
  : "${ICE_CONFIG_TOKEN:?ICE_CONFIG_TOKEN не задан}"
  if [[ "${ICE_CONFIG_TOKEN}" == REPLACE_* ]] || [[ "${ICE_CONFIG_TOKEN}" == *FROM_VPS* ]]; then
    say "замените ICE_CONFIG_TOKEN в ${ENV} (токен с VPS)"
    exit 2
  fi
}

ensure_python() {
  if [[ ! -x "${PY}" ]]; then
    say "нет ${PY} — создайте venv: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 2
  fi
}

stop_conflicts() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet webrtc-vps.service 2>/dev/null; then
      say "остановите webrtc-vps.service (конфликт с camstream): sudo systemctl disable --now webrtc-vps.service"
      exit 3
    fi
  fi
  local n
  n="$(pgrep -fc 'stream_camera\.py.*webrtc' 2>/dev/null || true)"
  if [[ "${n:-0}" -gt 0 ]]; then
    say "останавливаю ${n} процесс(ов) stream_camera webrtc…"
    pkill -TERM -f 'stream_camera\.py.*webrtc' 2>/dev/null || true
    sleep 0.5
    pkill -KILL -f 'stream_camera\.py.*webrtc' 2>/dev/null || true
  fi
  if pgrep -f 'rpicam-vid|libcamera-vid' >/dev/null 2>&1; then
    say "останавливаю зависший rpicam-vid…"
    pkill -TERM -f 'rpicam-vid|libcamera-vid' 2>/dev/null || true
    sleep 0.3
    pkill -KILL -f 'rpicam-vid|libcamera-vid' 2>/dev/null || true
  fi
}

check_vps() {
  if [[ -x "${ROOT}/scripts/verify_vps_webrtc.sh" ]]; then
    if ! "${ROOT}/scripts/verify_vps_webrtc.sh"; then
      say "VPS verify не прошёл — проверьте nginx/coturn на Hetzner и токен в ${ENV}"
      return 1
    fi
  else
    if ! curl -sf -m 8 -H "Authorization: Bearer ${ICE_CONFIG_TOKEN}" "${ICE_CONFIG_URL}" \
      | grep -q 'turn:'; then
      say "ICE API не отвечает или нет TURN — ${ICE_CONFIG_URL}"
      return 1
    fi
  fi
  return 0
}

reset_room() {
  say "сброс комнаты ${WEBRTC_ROOM:-pi-camera} на VPS…"
  "${ROOT}/scripts/camstream_webrtc.sh" --room-only
}

check_romeo() {
  if [[ ! -e /dev/ttyACM0 ]]; then
    say "Romeo USB (/dev/ttyACM0) не найден — телеметрия батареи может быть пустой"
  fi
}

start_service() {
  if [[ "${NO_START}" -eq 1 ]] || [[ "${CHECK_ONLY}" -eq 1 ]]; then
    return 0
  fi
  if [[ "${FOREGROUND}" -eq 1 ]]; then
    say "запуск на переднем плане: camstream_webrtc.sh -v"
    exec "${ROOT}/scripts/camstream_webrtc.sh" -v
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files camstream.service >/dev/null 2>&1; then
    if systemctl is-enabled --quiet camstream.service 2>/dev/null \
      || [[ -f /etc/systemd/system/camstream.service ]]; then
      say "sudo systemctl restart camstream.service"
      sudo systemctl restart camstream.service
      systemctl is-active --quiet camstream.service && say "camstream.service: active"
      return 0
    fi
  fi
  say "systemd camstream.service не найден — nohup camstream_webrtc.sh -v → ${LOG}"
  nohup "${ROOT}/scripts/camstream_webrtc.sh" -v >>"${LOG}" 2>&1 &
  sleep 2
  pgrep -af 'stream_camera\.py.*webrtc' || { say "WebRTC не запустился — см. ${LOG}"; exit 1; }
}

main() {
  cd "${ROOT}"
  ensure_webrtc_env
  ensure_python
  check_romeo
  stop_conflicts
  check_vps || exit 1
  [[ "${SKIP_ROOM_RESET}" -eq 1 ]] || reset_room
  if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    say "проверки OK (запуск пропущен: --check-only)"
    exit 0
  fi
  start_service
  say "готово. Браузер: http://116.203.148.254/cam?iceToken=<TOKEN>&room=${WEBRTC_ROOM:-pi-camera}&autostart=1"
}

main "$@"
