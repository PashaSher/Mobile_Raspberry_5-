#!/usr/bin/env python3
"""
Точка входа (как раньше): ``python stream_camera.py <команда>``.

Реализация разнесена по пакету ``rpi_tools/``:

- ``rpi_tools/camera_stream.py`` — камера, UDP/H.264, RTSP/H.264 и H.264/TCP пути, legacy JPEG/MJPEG по TCP, UDP discovery, ``send``.
- ``rpi_tools/romeo_usb.py`` — USB Romeo: прошивка (bootloader), ``serial-send``, ``adc-read`` / ``adc-cal`` (АЦП, VCC/VREF).
- ``rpi_tools/romeo_control_server.py`` — TCP с ПК → строки на Romeo (при ``send --listen``).
- ``rpi_tools/wifi_scan.py`` — ``wifi-scan`` (nmcli).
- ``rpi_tools/discovery.py`` — протокол UDP handshake.
- ``rpi_tools/config.py`` — ``ROMEO_USB_PORT``, пути к ``scripts/``, константы discovery.

- ``rpi_tools/boot_gpio_gate.py`` — при старте Pi: если GPIO (BCM) на земле → ``exec`` стрима, иначе выход без запуска (см. ``scripts/camstream-gpio-gate.service.example``).

Документация: клиент на ПК — ``docs/pc-remote-control.ru.md``; качество видео на Pi (H.264/JPEG, битрейт, разрешение) — ``docs/pi-stream-quality.ru.md``.

Примеры:

  python stream_camera.py send --listen
  # При --listen по умолчанию TCP :5001 принимает команды Romeo с ПК (см. --romeo-control-port).
  python stream_camera.py send --listen --stream-preset cinema
  python stream_camera.py send --video-mode udp_h264 --host 10.42.0.2 --port 5000 --stream-preset realtime
  python stream_camera.py send --ap-ssid 12345 --ap-force --video-mode udp_h264 --host 10.42.0.194 --port 5000 --stream-preset realtime
  python stream_camera.py send --listen --video-mode jpeg_tcp --port 5000 --no-set-fps
  python stream_camera.py serial-send
  python stream_camera.py romeo
  python stream_camera.py flash-romeo
  python stream_camera.py firebase-probe --firebase-cred bro-oppy-firebase-adminsdk-fbsvc-….json
  python stream_camera.py webrtc --firebase-cred … --firebase-db-url https://PROJECT-default-rtdb.firebaseio.com
  # Вне домашней сети (TURN на VPS): ICE_CONFIG_* или --ice-config-url / --ice-config-token (config/webrtc.ice.env.example).
  # Отладка только через Hetzner relay: webrtc … --ice-vps-only (Run and Debug: «webrtc via Hetzner only»).
  # Комната RTDB для WebRTC по умолчанию: pi-camera (см. examples/WEBRTC_ROOM_pi-camera.txt и examples/rtdb_room_pi_camera.js)
  python stream_camera.py wifi-scan
  python stream_camera.py wifi-connect "ИмяСети" --password-file ~/wifi.key
  # или: export RPI_WIFI_PASSWORD='...' && python stream_camera.py wifi-connect "ИмяСети"

Сохранённые настройки в проекте (файл в .gitignore, шаблон в репозитории):
  cp config/wifi.local.env.example config/wifi.local.env
  # отредактируйте wifi.local.env, пароль лучше в отдельном файле с chmod 600
  python stream_camera.py wifi-apply
  ./scripts/wifi_apply.sh

То же через модуль: ``python -m rpi_tools.cli ...``
"""

from __future__ import annotations

import os
import sys

from rpi_tools.cli import main
from rpi_tools.config import ROMEO_USB_PORT

__all__ = ["main", "ROMEO_USB_PORT"]

if __name__ == "__main__":
    _rc = main()
    if _rc:
        # os._exit: без SystemExit — иначе debugpy на Python 3.13 часто даёт IndexError в traceback.format
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(int(_rc))
