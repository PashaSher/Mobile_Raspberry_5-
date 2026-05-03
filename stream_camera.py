#!/usr/bin/env python3
"""
Точка входа (как раньше): ``python stream_camera.py <команда>``.

Реализация разнесена по пакету ``rpi_tools/``:

- ``rpi_tools/camera_stream.py`` — камера, MJPEG по TCP, UDP discovery, ``send``.
- ``rpi_tools/romeo_usb.py`` — USB Romeo: прошивка (bootloader) и ``serial-send`` / моторы.
- ``rpi_tools/wifi_scan.py`` — ``wifi-scan`` (nmcli).
- ``rpi_tools/discovery.py`` — протокол UDP handshake.
- ``rpi_tools/config.py`` — ``ROMEO_USB_PORT``, пути к ``scripts/``, константы discovery.

Примеры:

  python stream_camera.py send --listen --port 5000 --no-set-fps
  python stream_camera.py serial-send
  python stream_camera.py romeo
  python stream_camera.py flash-romeo
  python stream_camera.py wifi-scan

То же через модуль: ``python -m rpi_tools.cli ...``
"""

from __future__ import annotations

from rpi_tools.cli import main
from rpi_tools.config import ROMEO_USB_PORT

__all__ = ["main", "ROMEO_USB_PORT"]

if __name__ == "__main__":
    main()
