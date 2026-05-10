#!/usr/bin/env bash
# Запуск stream_camera через debugpy: ждёт подключение отладчика (Attach в Cursor).
# Вызывается из systemd после rpi_tools.boot_gpio_gate при GPIO17 → GND.
#
# Переменные (опционально):
#   CAMSTREAM_PYTHON  — интерпретатор (по умолчанию: <корень_проекта>/.venv/bin/python)
#   STREAM_CAMERA_SCRIPT — путь к stream_camera.py
#   DEBUGPY_LISTEN   — что слушать (по умолчанию 0.0.0.0:5678 для ПК по Wi‑Fi AP)
#
# Аргументы командной строки передаются в stream_camera после имени файла:
#   .../camstream_debugpy_listen.sh send --listen --port 5000
#
# Лог в файл как у boot_gpio_gate: CAMSTREAM_BOOT_LOG или ~/.local/share/camstream/camstream_boot.log
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${CAMSTREAM_PYTHON:-${ROOT}/.venv/bin/python}"
SPY="${STREAM_CAMERA_SCRIPT:-${ROOT}/stream_camera.py}"
LISTEN="${DEBUGPY_LISTEN:-0.0.0.0:5678}"
LOG_FILE="${CAMSTREAM_BOOT_LOG:-"${HOME}/.local/share/camstream/camstream_boot.log"}"
LOG_FILE="${LOG_FILE/#\~/${HOME}}"

boot_log() {
  local line
  line="$(date -Is) camstream_debugpy_listen: $*"
  echo "${line}" >&2
  if d="$(dirname -- "${LOG_FILE}")"; [[ -n "${d}" ]]; then
    mkdir -p -- "${d}" 2>/dev/null || true
  fi
  if ! printf '%s\n' "${line}" >>"${LOG_FILE}" 2>/dev/null; then
    echo "camstream_debugpy_listen: не записал строку в ${LOG_FILE}" >&2
  fi
}

boot_log "старт pid=$$ ROOT=${ROOT} PY=${PY} SPY=${SPY} LISTEN=${LISTEN} args=$* LOG_FILE=${LOG_FILE}"

if [[ ! -x "$PY" ]]; then
  boot_log "ошибка: нет интерпретатора: ${PY}"
  exit 1
fi
if [[ ! -f "$SPY" ]]; then
  boot_log "ошибка: не найден ${SPY}"
  exit 1
fi
if ! "$PY" -c "import debugpy" 2>/dev/null; then
  boot_log "ошибка: в venv нужен debugpy — ${PY} -m pip install debugpy"
  exit 1
fi

boot_log "exec debugpy wait-for-client ${SPY} $*"
exec "$PY" -m debugpy --listen "$LISTEN" --wait-for-client "$SPY" "${@}"
