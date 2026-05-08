"""Пути и константы проекта (порт Romeo, discovery, буферы TCP)."""

from __future__ import annotations

import os

# Каталог репозитория (родитель пакета rpi_tools)
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)

# USB CDC Romeo: serial и прошивка (см. scripts/flash_romeo_auto.sh, переменная ROMEO_PORT)
ROMEO_USB_PORT = "/dev/ttyACM0"
FLASH_ROMEO_AUTO_SH = os.path.join(PROJECT_ROOT, "scripts", "flash_romeo_auto.sh")

DISCOVERY_PORT_DEFAULT = 37020
# Отдельный TCP-порт для команд Romeo (ПК → Pi → USB); при --listen см. --romeo-control-port.
ROMEO_CONTROL_PORT_DEFAULT = 5001
ROMEO_TANK_SPEED_DEFAULT = 200

DISCOVERY_VERSION = 1
DISCOVERY_REQ = "discover"
DISCOVERY_RSP = "hello"

# TCP: при медленном приёмнике ядро не держит неограниченный объём RAM
_STREAM_SNDBUF = 256 * 1024
