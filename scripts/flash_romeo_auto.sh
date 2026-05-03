#!/usr/bin/env bash
# Автопрошивка Romeo/Leonardo (ATmega32U4) через USB на Raspberry Pi.
# Делает 1200-touch reset, прошивает через фиксированный порт ROMEO_PORT (по умолчанию /dev/ttyACM0),
# до 3 попыток. Порт задаётся в rpi_tools/config.py (ROMEO_USB_PORT) или: export ROMEO_PORT=/dev/ttyACM1
set -euo pipefail

HEX="${1:-$HOME/firmware.hex}"
ROMEO_PORT="${ROMEO_PORT:-/dev/ttyACM0}"
MAX_TRIES="${MAX_TRIES:-3}"
BAUD="${BAUD:-57600}"

if [[ ! -r "$HEX" ]]; then
  echo "Файл не найден или не читается: $HEX" >&2
  echo "Пример: $0 \$HOME/firmware.hex" >&2
  exit 1
fi

if ! command -v avrdude >/dev/null 2>&1; then
  echo "Не найден avrdude. Установите: sudo apt install -y avrdude" >&2
  exit 1
fi

touch_reset() {
  local port="$1"
  python3 - "$port" <<'PY'
import serial, sys
port = sys.argv[1]
s = serial.Serial(port, 1200, timeout=1)
s.close()
PY
}

flash_once() {
  local port="$1"
  avrdude -v -p atmega32u4 -c avr109 -P "$port" -b "$BAUD" -D -U "flash:w:${HEX}:i"
}

for try in $(seq 1 "$MAX_TRIES"); do
  echo "== Попытка $try/$MAX_TRIES ==" >&2

  if [[ ! -e "$ROMEO_PORT" ]]; then
    echo "Порт недоступен: $ROMEO_PORT (подключите Romeo или задайте ROMEO_PORT)." >&2
    sleep 1
    continue
  fi

  echo "Порт: $ROMEO_PORT; 1200-touch reset..." >&2
  if ! touch_reset "$ROMEO_PORT"; then
    echo "1200-touch не удался на $ROMEO_PORT, пробуем прошить без reset." >&2
  fi

  sleep 1.5
  if [[ ! -e "$ROMEO_PORT" ]]; then
    echo "После reset порт $ROMEO_PORT не найден, ждём и пробуем снова." >&2
    sleep 1
    continue
  fi

  echo "Прошивка через $ROMEO_PORT ..." >&2
  if flash_once "$ROMEO_PORT"; then
    echo "Готово: прошивка записана." >&2
    exit 0
  fi

  echo "Не удалось прошить через $ROMEO_PORT." >&2
  sleep 1
done

echo "Прошивка не удалась после $MAX_TRIES попыток." >&2
echo "Проверьте кабель/питание, нажмите RESET 2 раза и повторите." >&2
exit 1
