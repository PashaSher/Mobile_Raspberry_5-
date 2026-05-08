#!/usr/bin/env python3
"""
Точка входа (как раньше): ``python stream_camera.py <команда>``.

Реализация разнесена по пакету ``rpi_tools/``:

- ``rpi_tools/camera_stream.py`` — камера, MJPEG по TCP, UDP discovery, ``send``.
- ``rpi_tools/romeo_usb.py`` — USB Romeo: прошивка (bootloader) и ``serial-send`` / моторы.
- ``rpi_tools/romeo_control_server.py`` — TCP с ПК → строки на Romeo (при ``send --listen``).

Инструкция для разработчика клиента на ПК (подключение, порты, JSON): ``docs/pc-remote-control.ru.md``.
- ``rpi_tools/wifi_scan.py`` — ``wifi-scan`` (nmcli).
- ``rpi_tools/discovery.py`` — протокол UDP handshake.
- ``rpi_tools/config.py`` — ``ROMEO_USB_PORT``, пути к ``scripts/``, константы discovery.

Примеры:

  python stream_camera.py send --listen
  # При --listen по умолчанию TCP :5001 принимает команды Romeo с ПК (см. --romeo-control-port).
  python stream_camera.py send --listen --port 5000 --no-set-fps
  python stream_camera.py serial-send
  python stream_camera.py romeo
  python stream_camera.py flash-romeo
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

from rpi_tools.cli import main
from rpi_tools.config import ROMEO_USB_PORT

__all__ = ["main", "ROMEO_USB_PORT"]

if __name__ == "__main__":
    raise SystemExit(main())
