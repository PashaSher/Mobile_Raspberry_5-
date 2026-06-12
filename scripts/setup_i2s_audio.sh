#!/usr/bin/env bash
# I2S: MAX98357A (усилитель) + I2S-микрофон (INMP441 / ICS-43434 / SPH0645) на Raspberry Pi 5.
#
# Распиновка (BCM, 40-pin header):
#   GPIO 18 (pin 12) — BCLK  → SCK/BCLK на микрофоне и усилителе
#   GPIO 19 (pin 35) — LRCLK → WS/LRC на микрофоне и усилителе
#   GPIO 20 (pin 38) — DIN   → SD/DOUT микрофона (данные в Pi)
#   GPIO 21 (pin 40) — DOUT  → DIN усилителя (данные из Pi)
#   GPIO 16 (pin 36) — SD_MODE усилителя (управляется overlay googlevoicehat)
#   3.3V / 5V / GND — питание модулей
#
#   Микрофон: L/R (SEL) → GND (левый канал, моно)
#   Усилитель: SD → 3.3V (левый канал) или оставить GPIO16 от overlay
#
# Использование:
#   sudo ./scripts/setup_i2s_audio.sh           # config.txt + asound.conf
#   sudo ./scripts/setup_i2s_audio.sh --reboot  # и перезагрузка
#   ./scripts/setup_i2s_audio.sh --check        # проверка без root
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="/boot/firmware/config.txt"
ASOUND_DST="/etc/asound.conf"
REBOOT=0
CHECK_ONLY=0

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \?//'
  echo "Опции: --reboot  --check  -h"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reboot) REBOOT=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "setup_i2s_audio: неизвестный аргумент: $1" >&2; usage; exit 2 ;;
  esac
done

say() { echo "[setup_i2s_audio] $*" >&2; }

check_audio() {
  echo "=== ALSA cards ==="
  cat /proc/asound/cards 2>/dev/null || true
  echo "=== Capture (arecord -l) ==="
  arecord -l 2>/dev/null || true
  echo "=== Playback (aplay -l) ==="
  aplay -l 2>/dev/null || true
}

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  check_audio
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  say "нужен root: sudo $0"
  exit 1
fi

if [[ ! -f "${CONFIG}" ]]; then
  say "не найден ${CONFIG}"
  exit 1
fi

stamp="$(date +%Y%m%d-%H%M%S)"
cp -a "${CONFIG}" "${CONFIG}.bak.${stamp}"
say "резервная копия: ${CONFIG}.bak.${stamp}"

ensure_line() {
  local needle="$1"
  local line="$2"
  if grep -qF "${needle}" "${CONFIG}"; then
    say "уже есть: ${needle}"
  else
    printf '\n%s\n' "${line}" >> "${CONFIG}"
    say "добавлено: ${line}"
  fi
}

# I2S overlay: duplex (запись + воспроизведение) на одной шине.
ensure_line "dtparam=i2s=on" "dtparam=i2s=on"
ensure_line "dtoverlay=googlevoicehat-soundcard" "dtoverlay=googlevoicehat-soundcard"

# Маркер блока (для идемпотентности при ручных правках)
if ! grep -q "Mobile_Raspberry_5- I2S audio" "${CONFIG}"; then
  sed -i '/dtoverlay=googlevoicehat-soundcard/i\
# Mobile_Raspberry_5- I2S audio (MAX98357A + I2S mic)' "${CONFIG}" 2>/dev/null || true
fi

if [[ -f "${ASOUND_DST}" ]]; then
  cp -a "${ASOUND_DST}" "${ASOUND_DST}.bak.${stamp}"
  say "резервная копия: ${ASOUND_DST}.bak.${stamp}"
fi

# Карта googlevoicehat обычно card 2 (после vc4hdmi0/1), но надёжнее искать по имени.
CARD_ID=""
if [[ -r /proc/asound/cards ]]; then
  CARD_ID="$(awk 'tolower($0) ~ /voice|googlevoi/ { print $1; exit }' /proc/asound/cards)"
fi
if [[ -z "${CARD_ID}" ]]; then
  say "предупреждение: googlevoicehat не найден в /proc/asound/cards — используем card 2"
  CARD_ID="2"
fi

cat > "${ASOUND_DST}" <<EOF
# Mobile_Raspberry_5- I2S: googlevoicehat (MAX98357A + I2S mic), card ${CARD_ID}

pcm.i2s_hw {
    type plug
    slave.pcm "hw:${CARD_ID},0"
}

pcm.dmixer {
    type dmix
    ipc_key 1024
    ipc_perm 0666
    slave {
        pcm "i2s_hw"
        rate 48000
        channels 2
        period_size 1024
        buffer_size 8192
    }
}

pcm.!default {
    type asym
    playback.pcm "dmixer"
    capture.pcm "i2s_hw"
}

ctl.!default {
    type hw
    card ${CARD_ID}
}
EOF
say "записан ${ASOUND_DST}"

say "готово. После перезагрузки: arecord -l && aplay -l"
say "тест: arecord -d 3 -f S16_LE -r 48000 /tmp/i2s_test.wav && aplay /tmp/i2s_test.wav"

if [[ "${REBOOT}" -eq 1 ]]; then
  say "перезагрузка..."
  reboot
fi
