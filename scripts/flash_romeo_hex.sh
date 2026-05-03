#!/bin/sh
# Romeo как Arduino Leonardo (ATmega32U4) по USB на Raspberry Pi.
# Порт по умолчанию = ROMEO_USB_PORT в rpi_tools/config.py (обычно /dev/ttyACM0).
# 1) Скопируйте firmware.hex с ПК: scp .../firmware.hex pavel@rpi5-ar:~/
# 2) Закройте screen/minicom на этом порту.
# 3) При сбое загрузчика: двойной reset на плате и сразу запустите скрипт.
set -e
HEX="${1:?Укажите путь к .hex, например: $0 \$HOME/firmware.hex}"
PORT="${2:-/dev/ttyACM0}"
# avrdude не раскрывает ~ в -U flash:w:... — только полный путь или \$HOME/...
case "$HEX" in
	"~") HEX="$HOME" ;;
	"~"/*) HEX="$HOME/${HEX#~/}" ;;
esac
test -r "$HEX" || { echo "Файл не найден или не читается: $HEX" >&2; exit 1; }
test -e "$PORT" || { echo "Порт не найден: $PORT (подключите Romeo по USB)" >&2; exit 1; }
exec avrdude -v -p atmega32u4 -c avr109 -P "$PORT" -b 57600 -D -U "flash:w:${HEX}:i"
