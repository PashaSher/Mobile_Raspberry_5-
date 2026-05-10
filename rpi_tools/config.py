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
# JSON drive left/right: поворот на месте через TANK ±mag (mag = tank_speed × scale), не TL/TR — мягче разворот.
ROMEO_PIVOT_TANK_SCALE = 0.5
# JSON башня: скорости PL/PANV/TILTV/TURRETV (град/с) умножаются на этот коэффициент.
ROMEO_TURRET_VEL_SCALE = 0.5
# JSON turret step / --romeo-turret-step: шаг PANL… (°) умножается на этот коэффициент.
ROMEO_TURRET_STEP_SCALE = 0.5

DISCOVERY_VERSION = 1
DISCOVERY_REQ = "discover"
DISCOVERY_RSP = "hello"

# TCP: буфер отправки (720p30 MJPEG — меньше дропов при всплесках JPEG)
_STREAM_SNDBUF = 2 * 1024 * 1024

# Слотов очереди отправки JPEG (отдельный поток): кодер не блокируется, если ПК/Wi‑Fi читают медленно.
# 0 — старый режим (sendall сразу из потока кодирования).
JPEG_TCP_QUEUE_DEPTH_DEFAULT = 2


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# Делитель на входе АЦП (аккумулятор → узел A0): R верх к «+», R низ к GND.
# V_акб = V_на_пине × (R1 + R2) / R2. По умолчанию 47k/10k → коэффициент 5.7.
# Если номиналы другие — перемерьте резисторы или задайте по двум точкам:
#   export ROMEO_BATTERY_DIVIDER_R1_OHM=26411   # пример: Ubat/Ua0×R2−R2 при R2=10k (17.33В / 4.76В)
#   export ROMEO_BATTERY_DIVIDER_R2_OHM=10000
ROMEO_BATTERY_DIVIDER_R1_OHM = _int_env("ROMEO_BATTERY_DIVIDER_R1_OHM", 47_000)
ROMEO_BATTERY_DIVIDER_R2_OHM = _int_env("ROMEO_BATTERY_DIVIDER_R2_OHM", 10_000)


def _adc_default_channel() -> int:
    """Индекс канала АЦП по умолчанию (0=A0 … 5=A5). Переменная ROMEO_ADC_DEFAULT_CHANNEL."""
    v = _int_env("ROMEO_ADC_DEFAULT_CHANNEL", 1)
    return max(0, min(5, v))


ROMEO_ADC_DEFAULT_CHANNEL = _adc_default_channel()


def _adc_firmware_mv_scale() -> float:
    """Масштаб: правда на пине / то, что считает прошивка в поле millivolts (см. ADC_CALIBRATION)."""
    raw = os.environ.get("ROMEO_ADC_FIRMWARE_MV_SCALE", "").strip()
    if not raw:
        return 1.0
    try:
        return float(raw)
    except ValueError:
        return 1.0


# Умножитель к полю millivolts из ответа прошивки (A0 …), если опора AVCC в скетче ≠ реальности.
# Одна точка калибровки: scale = U_мультиметр_на_пине_mV / U_из_строки_прошивки_mV.
# Пример: на пине 3010 mV, в ответе 4648 → export ROMEO_ADC_FIRMWARE_MV_SCALE=0.6476
ROMEO_ADC_FIRMWARE_MV_SCALE = _adc_firmware_mv_scale()


def _battery_display_scale() -> float:
    """Множитель после формулы делителя. По умолчанию: при ~3.07 В на пине → 18 В на АКБ (замер)."""
    raw = os.environ.get("ROMEO_BATTERY_V_SCALE", "").strip()
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    r1 = float(ROMEO_BATTERY_DIVIDER_R1_OHM)
    r2 = float(ROMEO_BATTERY_DIVIDER_R2_OHM)
    pin_v = 3.07  # В на входе АЦП при реальных 18 В на аккумуляторе (мультиметр)
    u_bat = 18.0
    est = pin_v * (r1 + r2) / r2
    return u_bat / est if est > 0 else 1.0


# Финальная калибровка после делителя: по умолчанию считается из замера U_пин≈3.07 В ↔ U_акб=18 В.
# Свой коэффициент: export ROMEO_BATTERY_V_SCALE=1.03
ROMEO_BATTERY_V_SCALE = _battery_display_scale()

# --- Калибровка индикатора батареи (после делителя и ROMEO_BATTERY_V_SCALE) ---
# По умолчанию: две точки (U_romeo, U_мультиметр) → линейная формула U = a·U_romeo + b (точно по обеим).
# Переопределение точек: ROMEO_BATTERY_CAL_R1, ROMEO_BATTERY_CAL_U1, ROMEO_BATTERY_CAL_R2, ROMEO_BATTERY_CAL_U2
#
# Режим ROMEO_BATTERY_DISPLAY_CALIB:
#   affine — по умолчанию; scale — только множитель ROMEO_BATTERY_VOLTAGE_SCALE; linear — свои a,b в env;
#   off — без поправки.
# Доп. поправка после делителя и ROMEO_BATTERY_V_SCALE: по умолчанию тождество (a=1, b=0).
# Две точки (U_est, U_экран) при необходимости: ROMEO_BATTERY_CAL_R1/U1/R2/U2
_DEFAULT_BATTERY_CAL_R1 = 0.0
_DEFAULT_BATTERY_CAL_U1 = 0.0
_DEFAULT_BATTERY_CAL_R2 = 1.0
_DEFAULT_BATTERY_CAL_U2 = 1.0


def _battery_affine_ab_from_cal_pairs() -> tuple[float, float]:
    r1 = _float_env("ROMEO_BATTERY_CAL_R1", _DEFAULT_BATTERY_CAL_R1)
    u1 = _float_env("ROMEO_BATTERY_CAL_U1", _DEFAULT_BATTERY_CAL_U1)
    r2 = _float_env("ROMEO_BATTERY_CAL_R2", _DEFAULT_BATTERY_CAL_R2)
    u2 = _float_env("ROMEO_BATTERY_CAL_U2", _DEFAULT_BATTERY_CAL_U2)
    dr = r2 - r1
    if abs(dr) < 1e-9:
        return 1.0, 0.0
    a = (u2 - u1) / dr
    b = u1 - a * r1
    return a, b


ROMEO_BATTERY_CAL_A, ROMEO_BATTERY_CAL_B = _battery_affine_ab_from_cal_pairs()

# Только для режима scale: U_out = U_in × k (если не задано в env — 1.0).
_DEFAULT_BATTERY_VOLTAGE_SCALE = 1.0


def _romeo_battery_voltage_scale_from_env() -> float:
    raw = os.environ.get("ROMEO_BATTERY_VOLTAGE_SCALE", "").strip()
    if not raw:
        return _DEFAULT_BATTERY_VOLTAGE_SCALE
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_BATTERY_VOLTAGE_SCALE


ROMEO_BATTERY_VOLTAGE_SCALE = _romeo_battery_voltage_scale_from_env()


def _battery_display_calib_mode() -> str:
    return os.environ.get("ROMEO_BATTERY_DISPLAY_CALIB", "affine").strip().lower()


def _battery_linear_calib_ab() -> tuple[float, float]:
    """U_out = a * U_Romeo + b при ROMEO_BATTERY_DISPLAY_CALIB=linear."""
    raw = os.environ.get("ROMEO_BATTERY_DISPLAY_LINEAR", "").strip()
    if raw:
        parts = raw.replace(",", " ").split()
        if len(parts) >= 2:
            try:
                return float(parts[0]), float(parts[1])
            except ValueError:
                pass
    try:
        a = float(os.environ.get("ROMEO_BATTERY_DISPLAY_LINEAR_A", "1"))
        b = float(os.environ.get("ROMEO_BATTERY_DISPLAY_LINEAR_B", "0"))
        return a, b
    except ValueError:
        return 1.0, 0.0


def battery_display_volts_to_multimeter(display_v: float) -> float:
    """
    Поправка U с Romeo для отображения.
    По умолчанию affine: U = ROMEO_BATTERY_CAL_A * U_romeo + ROMEO_BATTERY_CAL_B (две точки в коде/env).
    """
    mode = _battery_display_calib_mode()
    if mode == "lut":
        mode = "affine"
    if mode in ("0", "off", "none", "false"):
        return float(display_v)
    if mode == "linear":
        a, b = _battery_linear_calib_ab()
        return float(display_v) * a + b
    if mode in ("scale", "simple", "mul"):
        return float(display_v) * ROMEO_BATTERY_VOLTAGE_SCALE
    return float(display_v) * ROMEO_BATTERY_CAL_A + ROMEO_BATTERY_CAL_B


ROMEO_BATTERY_MONITOR_USE_VBAT = os.environ.get("ROMEO_BATTERY_MONITOR_USE_VBAT", "").strip().lower() in (
    "1",
    "true",
    "yes",
)


def adc_pin_mv_calibrated(pin_mv_from_firmware: float) -> float:
    """Милливольты на выводе АЦП после поправки шкалы (не те же, что сырые из UART)."""
    return float(pin_mv_from_firmware) * ROMEO_ADC_FIRMWARE_MV_SCALE


def battery_volts_from_adc_pin_mv(pin_mv_from_firmware: float) -> float:
    """Напряжение на аккумуляторе (В): делитель, ROMEO_BATTERY_V_SCALE и battery_display_volts_to_multimeter."""
    pin_mv = adc_pin_mv_calibrated(pin_mv_from_firmware)
    r1 = float(ROMEO_BATTERY_DIVIDER_R1_OHM)
    r2 = float(ROMEO_BATTERY_DIVIDER_R2_OHM)
    est = pin_mv * (r1 + r2) / r2 / 1000.0 * ROMEO_BATTERY_V_SCALE
    return battery_display_volts_to_multimeter(est)
