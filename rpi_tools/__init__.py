"""
Утилиты Raspberry Pi: камера/TCP-стрим, UDP discovery, Romeo USB (моторы/прошивка), Wi‑Fi.

Точка входа CLI: ``python stream_camera.py`` или ``python -m rpi_tools.cli``.
Модули: ``camera_stream``, ``discovery``, ``romeo_usb``, ``wifi_scan``, ``wifi_connect`` (в т.ч. ``wifi-apply``), ``config``.
"""

from rpi_tools.config import ROMEO_USB_PORT

__all__ = ["ROMEO_USB_PORT"]
