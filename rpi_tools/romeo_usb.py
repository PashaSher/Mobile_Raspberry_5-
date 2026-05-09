"""Romeo по USB: прошивка (bootloader) и обмен строками с прошивкой (моторы, серво и т.д.)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time

from rpi_tools.config import FLASH_ROMEO_AUTO_SH, ROMEO_USB_PORT

log = logging.getLogger("camstream")

# Один USB CDC — один писатель (стрим + CLI + TCP не должны мешать друг другу).
_ROMEO_IO_LOCK = threading.Lock()


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


def romeo_exchange(
    port: str,
    baud: int,
    text: str,
    *,
    append_lf: bool = True,
    read_timeout: float = 3.0,
    read_idle: float = 0.25,
    open_delay: float = 0.0,
    log_send: bool = True,
) -> bytes:
    """
    Отправка одной строки UTF-8 на Romeo и чтение ответа (до таймаута).
    Потокобезопасно относительно других вызовов romeo_exchange/run_serial_send.
    """
    try:
        import serial
    except ImportError:
        raise RuntimeError("Нужен pyserial: pip install pyserial (или apt install python3-serial)") from None
    dev = port
    if not os.path.exists(dev):
        raise OSError(f"USB-порт не найден: {dev}")
    payload = text.encode("utf-8", errors="replace")
    if append_lf:
        payload += b"\n"
    with _ROMEO_IO_LOCK:
        with serial.Serial(dev, baud, timeout=0.1, dsrdtr=False, rtscts=False) as ser:
            if open_delay > 0:
                if log_send:
                    log.info("serial-send: пауза %.1f с после открытия порта (загрузка скетча)", open_delay)
                time.sleep(open_delay)
            ser.reset_input_buffer()
            ser.write(payload)
            ser.flush()
            if log_send:
                log.info("serial-send: отправлено %d байт на %s @ %s", len(payload), dev, baud)
            return _serial_read_until_idle(ser, read_timeout, read_idle)


def start_romeo_led_heartbeat(
    *,
    port: str | None,
    baud: int,
    interval_sec: float,
    open_delay: float = 0.0,
) -> tuple[threading.Thread | None, threading.Event | None]:
    """
    Запускает daemon-поток: раз в ``interval_sec`` сек отправляет строку LTG на Romeo (toggle бортового LED).
    Совместимо с Romeo TCP→USB тем же блокировкой ``_ROMEO_IO_LOCK``.
    """
    device = port or ROMEO_USB_PORT
    if interval_sec <= 0:
        return None, None
    stop = threading.Event()

    def _worker() -> None:
        log.info(
            "Romeo heartbeat: LTG каждые %.1f с на %s @ %s (toggle LED по прошивке)",
            interval_sec,
            device,
            baud,
        )
        od0 = float(open_delay) if open_delay > 0 else 0.0
        use_open_delay = od0 > 0
        while True:
            if stop.wait(interval_sec):
                break
            try:
                if not os.path.exists(device):
                    log.debug("Romeo heartbeat: порт не найден: %s", device)
                    continue
                od_this = od0 if use_open_delay else 0.0
                romeo_exchange(
                    device,
                    baud,
                    "LTG",
                    append_lf=True,
                    read_timeout=0.35,
                    read_idle=0.06,
                    open_delay=od_this,
                    log_send=False,
                )
                use_open_delay = False
            except RuntimeError as e:
                log.warning("Romeo heartbeat недоступен: %s", e)
                break
            except OSError as e:
                log.debug("Romeo heartbeat LTG: %s", e)

    th = threading.Thread(target=_worker, name="romeo-led-heartbeat", daemon=True)
    th.start()
    return th, stop


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
    if not os.path.exists(port):
        log.error(
            "USB-порт не найден: %s (задайте порт в rpi_tools/config.py, ROMEO_USB_PORT, или --port)",
            port,
        )
        sys.exit(1)
    log.info("serial-send: порт %s", port)
    try:
        reply = romeo_exchange(
            port,
            baud,
            text,
            append_lf=append_lf,
            read_timeout=read_timeout,
            read_idle=read_idle,
            open_delay=open_delay,
            log_send=True,
        )
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    except OSError as e:
        log.error("Serial %s: %s (группа dialout? закройте монитор порта)", port, e)
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
