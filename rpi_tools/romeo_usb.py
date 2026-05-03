"""Romeo по USB: прошивка (bootloader) и обмен строками с прошивкой (моторы, серво и т.д.)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time

from rpi_tools.config import FLASH_ROMEO_AUTO_SH, ROMEO_USB_PORT

log = logging.getLogger("camstream")


def run_flash_romeo(hex_path: str) -> None:
    """Прошивка ATmega32U4 через ``scripts/flash_romeo_auto.sh``."""
    hex_path = os.path.expanduser(hex_path)
    if not os.path.isfile(FLASH_ROMEO_AUTO_SH):
        log.error("Нет скрипта прошивки (ожидался файл в репозитории): %s", FLASH_ROMEO_AUTO_SH)
        sys.exit(1)
    if not os.access(FLASH_ROMEO_AUTO_SH, os.X_OK):
        try:
            os.chmod(FLASH_ROMEO_AUTO_SH, 0o755)
        except OSError:
            pass
    if not os.path.isfile(hex_path):
        log.error("Файл прошивки не найден: %s (скопируйте .hex с ПК через scp)", hex_path)
        sys.exit(1)
    log.info("bootloader: %s %s (порт %s)", FLASH_ROMEO_AUTO_SH, hex_path, ROMEO_USB_PORT)
    env = {**os.environ, "ROMEO_PORT": ROMEO_USB_PORT}
    r = subprocess.run(["bash", FLASH_ROMEO_AUTO_SH, hex_path], check=False, env=env)
    sys.exit(r.returncode)


def _serial_read_until_idle(ser, read_timeout: float, read_idle: float) -> bytes:
    deadline = time.monotonic() + read_timeout
    buf = bytearray()
    last_rx = time.monotonic()
    poll = 0.01
    while time.monotonic() < deadline:
        n = ser.in_waiting
        if n:
            buf.extend(ser.read(n))
            last_rx = time.monotonic()
        elif buf and (time.monotonic() - last_rx) >= read_idle:
            break
        time.sleep(poll)
    return bytes(buf)


def run_serial_send(
    port: str,
    baud: int,
    text: str,
    append_lf: bool,
    read_timeout: float,
    read_idle: float,
    open_delay: float,
) -> None:
    """Отправка UTF-8 на USB CDC и чтение ответа."""
    try:
        import serial
    except ImportError:
        log.error("Нужен pyserial: pip install pyserial (или apt install python3-serial)")
        sys.exit(1)
    dev = port
    if not os.path.exists(dev):
        log.error(
            "USB-порт не найден: %s (задайте порт в rpi_tools/config.py, ROMEO_USB_PORT, или --port)",
            dev,
        )
        sys.exit(1)
    log.info("serial-send: порт %s", dev)
    payload = text.encode("utf-8", errors="replace")
    if append_lf:
        payload += b"\n"
    try:
        with serial.Serial(dev, baud, timeout=0.1, dsrdtr=False, rtscts=False) as ser:
            if open_delay > 0:
                log.info("serial-send: пауза %.1f с после открытия порта (загрузка скетча)", open_delay)
                time.sleep(open_delay)
            ser.reset_input_buffer()
            ser.write(payload)
            ser.flush()
            log.info("serial-send: отправлено %d байт на %s @ %s", len(payload), dev, baud)
            reply = _serial_read_until_idle(ser, read_timeout, read_idle)
    except OSError as e:
        log.error("Serial %s: %s (группа dialout? закройте монитор порта)", dev, e)
        sys.exit(1)
    if reply:
        dec = reply.decode("utf-8", errors="replace")
        log.info("ответ (%d байт): %r", len(reply), dec)
        sys.stdout.write(dec)
        if not reply.endswith(b"\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        log.warning(
            "ответа нет за %.1f с: попробуйте --baud 9600, --open-delay 2 (перезагрузка при открытии порта), "
            "--read-timeout; при необходимости сырой ввод без \\n: --no-nl; в скетче должен быть ответ в Serial.",
            read_timeout,
        )
