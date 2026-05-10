"""Romeo по USB: прошивка (bootloader) и обмен строками с прошивкой (моторы, серво и т.д.)."""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
import sys
import threading
import time

from rpi_tools.config import (
    FLASH_ROMEO_AUTO_SH,
    ROMEO_ADC_DEFAULT_CHANNEL,
    ROMEO_USB_PORT,
    adc_pin_mv_calibrated,
    battery_display_volts_to_multimeter,
    battery_volts_from_adc_pin_mv,
)

log = logging.getLogger("camstream")

# Сколько аналоговых каналов в прошивке (A0..A5 — совпадает с cfg::kAdcChannels).
ROMEO_ADC_CHANNEL_COUNT = 6

# Один USB CDC — один писатель (стрим + CLI + TCP не должны мешать друг другу).
_ROMEO_IO_LOCK = threading.Lock()
# Долгоживущий Serial: открывать/закрывать порт на каждую команду даёт рывки (CDC + задержки ОС).
_romeo_shared_ser = None
_romeo_shared_key: tuple[str, int] | None = None


def _romeo_close_shared_serial() -> None:
    global _romeo_shared_ser, _romeo_shared_key
    if _romeo_shared_ser is not None:
        try:
            _romeo_shared_ser.close()
        except OSError:
            pass
        _romeo_shared_ser = None
        _romeo_shared_key = None


atexit.register(_romeo_close_shared_serial)


def _romeo_ensure_serial(port: str, baud: int) -> tuple[object, bool]:
    """Возвращает (Serial, newly_opened)."""
    global _romeo_shared_ser, _romeo_shared_key
    try:
        import serial
    except ImportError:
        raise RuntimeError("Нужен pyserial: pip install pyserial (или apt install python3-serial)") from None
    key = (port, baud)
    ser = _romeo_shared_ser
    if ser is not None and _romeo_shared_key == key:
        try:
            if ser.is_open:
                return ser, False
        except (OSError, AttributeError, ValueError):
            pass
        _romeo_close_shared_serial()
    ser = serial.Serial(
        port,
        baud,
        timeout=0.1,
        write_timeout=0.5,
        dsrdtr=False,
        rtscts=False,
    )
    _romeo_shared_ser = ser
    _romeo_shared_key = key
    return ser, True


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


def parse_adc_reply(data: bytes) -> tuple[int, int, int]:
    """
    Разбор ответа прошивки на «A0»/«A 3» — строка вида «A<n> <raw> <millivolts>».
    Возвращает (номер_канала, raw 0..1023, мВ).
    """
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.upper().startswith("ERR"):
            raise ValueError(s)
        parts = s.split()
        if len(parts) < 3:
            continue
        tag = parts[0]
        if len(tag) < 2 or tag[0].upper() != "A" or not tag[1:].isdigit():
            continue
        ch = int(tag[1:])
        raw = int(parts[1])
        mv = int(parts[2])
        return ch, raw, mv
    raise ValueError(f"нет строки АЦП в ответе: {text!r}")


def parse_vbat_reply(data: bytes) -> tuple[int, int, int]:
    """
    Разбор ответа «VBAT <battery_mV> <raw> <pin_mV>» (прошивка, делитель на A1).
    Возвращает (battery_mV, raw, pin_mV).
    """
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.upper().startswith("ERR"):
            raise ValueError(s)
        parts = s.split()
        if len(parts) < 4:
            continue
        if parts[0].upper() != "VBAT":
            continue
        try:
            return int(parts[1]), int(parts[2]), int(parts[3])
        except ValueError as e:
            raise ValueError(s) from e
    raise ValueError(f"нет строки VBAT в ответе: {text!r}")


def romeo_read_vbat(
    port: str,
    baud: int,
    *,
    read_timeout: float = 1.0,
    read_idle: float = 0.12,
    open_delay: float = 0.0,
) -> tuple[int, int, int]:
    """Команда VBAT + LF — напряжение батареи по прошивке (мВ на аккумуляторе)."""
    reply = romeo_exchange(
        port,
        baud,
        "VBAT",
        append_lf=True,
        read_timeout=read_timeout,
        read_idle=read_idle,
        open_delay=open_delay,
        log_send=False,
    )
    if not reply.strip():
        raise ValueError("пустой ответ на VBAT")
    return parse_vbat_reply(reply)


def romeo_read_adc(
    port: str,
    baud: int,
    channel: int = ROMEO_ADC_DEFAULT_CHANNEL,
    *,
    read_timeout: float = 1.0,
    read_idle: float = 0.12,
    open_delay: float = 0.0,
) -> tuple[int, int, int]:
    """Опрос одного канала АЦП (команда «A<n>» + LF)."""
    if channel < 0 or channel >= ROMEO_ADC_CHANNEL_COUNT:
        raise ValueError(f"канал АЦП вне 0..{ROMEO_ADC_CHANNEL_COUNT - 1}: {channel}")
    cmd = f"A{int(channel)}"
    reply = romeo_exchange(
        port,
        baud,
        cmd,
        append_lf=True,
        read_timeout=read_timeout,
        read_idle=read_idle,
        open_delay=open_delay,
        log_send=False,
    )
    if not reply.strip():
        raise ValueError(
            "пустой ответ на команду АЦП (таймаут USB, другая скорость --baud или прошивка не отвечает)"
        )
    return parse_adc_reply(reply)


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
    Serial держится открытым между вызовами (меньше рывков TCP→USB).
    """
    dev = port
    if not os.path.exists(dev):
        raise OSError(f"USB-порт не найден: {dev}")
    payload = text.encode("utf-8", errors="replace")
    if append_lf:
        payload += b"\n"

    for attempt in range(2):
        with _ROMEO_IO_LOCK:
            try:
                ser, new = _romeo_ensure_serial(dev, baud)
                if new and open_delay > 0:
                    if log_send:
                        log.info(
                            "serial-send: пауза %.1f с после первого открытия порта (загрузка скетча)",
                            open_delay,
                        )
                    time.sleep(open_delay)
                ser.reset_input_buffer()
                ser.write(payload)
                ser.flush()
                if log_send:
                    log.info("serial-send: отправлено %d байт на %s @ %s", len(payload), dev, baud)
                return _serial_read_until_idle(ser, read_timeout, read_idle)
            except OSError:
                _romeo_close_shared_serial()
                if attempt == 1:
                    raise


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


def start_romeo_adc_monitor(
    *,
    port: str | None,
    baud: int,
    interval_sec: float,
    channel: int = ROMEO_ADC_DEFAULT_CHANNEL,
    open_delay: float = 0.0,
    use_vbat: bool = False,
) -> tuple[threading.Thread | None, threading.Event | None]:
    """
    Периодически опрашивает АЦП (A<n>) или команду VBAT (батарея в прошивке на A1).
    Использует ту же блокировку, что и TCP→USB и LTG heartbeat.
    """
    device = port or ROMEO_USB_PORT
    if interval_sec <= 0:
        return None, None
    if not use_vbat and (channel < 0 or channel >= ROMEO_ADC_CHANNEL_COUNT):
        log.warning("Romeo ADC: канал %s вне диапазона — мониторинг отключён", channel)
        return None, None
    stop = threading.Event()

    def _worker() -> None:
        if use_vbat:
            log.info(
                "Romeo VBAT: каждые %.1f с на %s @ %s",
                interval_sec,
                device,
                baud,
            )
        else:
            log.info(
                "Romeo ADC: опрос A%d каждые %.1f с на %s @ %s",
                channel,
                interval_sec,
                device,
                baud,
            )
        od0 = float(open_delay) if open_delay > 0 else 0.0
        use_open_delay = od0 > 0
        while True:
            try:
                if not os.path.exists(device):
                    log.debug("Romeo ADC/VBAT: порт не найден: %s", device)
                    if stop.wait(interval_sec):
                        break
                    continue
                od_this = od0 if use_open_delay else 0.0
                if use_vbat:
                    bat_mv, raw, pin_mv = romeo_read_vbat(
                        device,
                        baud,
                        read_timeout=1.0,
                        read_idle=0.12,
                        open_delay=od_this,
                    )
                    use_open_delay = False
                    u_fw = bat_mv / 1000.0
                    u_corr = battery_display_volts_to_multimeter(u_fw)
                    log.info(
                        "Romeo VBAT: прошивка=%.2f V оценка_мультим=%.2f V raw=%d pin=%d mV",
                        u_fw,
                        u_corr,
                        raw,
                        pin_mv,
                    )
                else:
                    ch, raw, mv = romeo_read_adc(
                        device,
                        baud,
                        channel,
                        read_timeout=1.0,
                        read_idle=0.12,
                        open_delay=od_this,
                    )
                    use_open_delay = False
                    ubat = battery_volts_from_adc_pin_mv(mv)
                    log.info(
                        "Romeo ADC: A%d raw=%d pin=%d mV Ubat≈%.2f V",
                        ch,
                        raw,
                        mv,
                        ubat,
                    )
            except ValueError as e:
                log.warning("Romeo ADC/VBAT: %s", e)
            except RuntimeError as e:
                log.warning("Romeo ADC/VBAT недоступен: %s", e)
                break
            except OSError as e:
                log.debug("Romeo ADC/VBAT: %s", e)
            if stop.wait(interval_sec):
                break

    th = threading.Thread(
        target=_worker,
        name="romeo-vbat-monitor" if use_vbat else "romeo-adc-monitor",
        daemon=True,
    )
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


def run_adc_read(
    port: str,
    baud: int,
    channel: int,
    read_timeout: float,
    read_idle: float,
    open_delay: float,
) -> None:
    """CLI: одна строка «A<n> raw mV» в stdout (как в прошивке), код выхода 0 или 1."""
    if not os.path.exists(port):
        log.error(
            "USB-порт не найден: %s (задайте порт в rpi_tools/config.py, ROMEO_USB_PORT, или --port)",
            port,
        )
        sys.exit(1)
    try:
        ch, raw, mv = romeo_read_adc(
            port,
            baud,
            channel,
            read_timeout=read_timeout,
            read_idle=read_idle,
            open_delay=open_delay,
        )
    except ValueError as e:
        log.error("%s", e)
        sys.exit(1)
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    except OSError as e:
        log.error("Serial %s: %s", port, e)
        sys.exit(1)
    ubat = battery_volts_from_adc_pin_mv(mv)
    cal_mv = adc_pin_mv_calibrated(mv)
    sys.stdout.write(f"A{ch} {raw} {mv}\n")
    sys.stdout.write(f"pin_V {cal_mv / 1000.0:.2f}\n")
    sys.stdout.write(f"battery_V {ubat:.2f}\n")
    sys.stdout.flush()


def run_vbat_read(
    port: str,
    baud: int,
    read_timeout: float,
    read_idle: float,
    open_delay: float,
) -> None:
    """CLI: строка VBAT из прошивки + battery_V (affine или scale — см. config)."""
    if not os.path.exists(port):
        log.error(
            "USB-порт не найден: %s (задайте порт в rpi_tools/config.py, ROMEO_USB_PORT, или --port)",
            port,
        )
        sys.exit(1)
    try:
        bat_mv, raw, pin_mv = romeo_read_vbat(
            port,
            baud,
            read_timeout=read_timeout,
            read_idle=read_idle,
            open_delay=open_delay,
        )
    except ValueError as e:
        log.error("%s", e)
        sys.exit(1)
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    except OSError as e:
        log.error("Serial %s: %s", port, e)
        sys.exit(1)
    u_fw = bat_mv / 1000.0
    u_corr = battery_display_volts_to_multimeter(u_fw)
    sys.stdout.write(f"VBAT {bat_mv} {raw} {pin_mv}\n")
    sys.stdout.write(f"battery_V_firmware {u_fw:.2f}\n")
    sys.stdout.write(f"battery_V {u_corr:.2f}\n")
    sys.stdout.flush()


def run_adc_cal(
    port: str,
    baud: int,
    mode: str,
    vref_mv: int | None,
    read_timeout: float,
    read_idle: float,
    open_delay: float,
) -> None:
    """CLI: VCC, VREF, VREF <mV>, VREF AUTO — сырой ответ прошивки в stdout."""
    if not os.path.exists(port):
        log.error(
            "USB-порт не найден: %s (задайте порт в rpi_tools/config.py, ROMEO_USB_PORT, или --port)",
            port,
        )
        sys.exit(1)
    if mode == "vcc":
        cmd = "VCC"
    elif mode == "vref-auto":
        cmd = "VREF AUTO"
    elif mode == "vref":
        cmd = f"VREF {int(vref_mv)}" if vref_mv is not None else "VREF"
    else:
        log.error("внутренняя ошибка: неизвестный mode=%r", mode)
        sys.exit(1)
    try:
        reply = romeo_exchange(
            port,
            baud,
            cmd,
            append_lf=True,
            read_timeout=read_timeout,
            read_idle=read_idle,
            open_delay=open_delay,
            log_send=True,
        )
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    except OSError as e:
        log.error("Serial %s: %s", port, e)
        sys.exit(1)
    if not reply.strip():
        log.warning("пустой ответ (для VCC увеличьте --read-timeout; bandgap измерение может быть долгим)")
        sys.exit(1)
    dec = reply.decode("utf-8", errors="replace")
    sys.stdout.write(dec)
    if not reply.endswith(b"\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()
