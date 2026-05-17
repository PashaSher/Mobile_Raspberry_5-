"""Телеметрия Pi для VPS/Firebase host: батарея (Romeo) и Wi‑Fi (nmcli)."""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Any

from rpi_tools.config import ROMEO_BATTERY_MONITOR_USE_VBAT, battery_display_volts_to_multimeter

log = logging.getLogger("camstream.telemetry")


def _run_nmcli(args: list[str], *, timeout: float = 8.0) -> str:
    r = subprocess.run(
        ["nmcli", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "nmcli error").strip())
    return r.stdout


def read_wifi_status(ifname: str | None = None) -> dict[str, Any]:
    """
    Текущая Wi‑Fi-связь через NetworkManager.

    Возвращает signal_percent (0–100), ssid, rate, channel, connected.
    """
    out: dict[str, Any] = {
        "connected": False,
        "ssid": None,
        "signal_percent": None,
        "rate": None,
        "channel": None,
        "device": ifname,
    }
    try:
        dev = (ifname or "").strip()
        if not dev:
            status = _run_nmcli(["-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"])
            for line in status.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[1] == "wifi" and parts[2] == "connected":
                    dev = parts[0]
                    break
        if dev:
            out["device"] = dev

        wifi_lines = _run_nmcli(
            ["-t", "-f", "ACTIVE,SSID,SIGNAL,CHAN,RATE", "device", "wifi", "list"],
        ).splitlines()
        for line in wifi_lines:
            parts = line.split(":")
            if len(parts) < 3:
                continue
            active = parts[0].strip().lower()
            if active in ("yes", "*"):
                out["connected"] = True
                out["ssid"] = parts[1] or None
                try:
                    out["signal_percent"] = int(parts[2])
                except ValueError:
                    pass
                if len(parts) > 3 and parts[3]:
                    try:
                        out["channel"] = int(parts[3])
                    except ValueError:
                        out["channel"] = parts[3]
                if len(parts) > 4 and parts[4]:
                    out["rate"] = parts[4]
                break

        if dev and not out["connected"]:
            try:
                show = _run_nmcli(["-t", "-f", "GENERAL.STATE", "device", "show", dev])
                out["connected"] = "connected" in show.lower()
            except Exception:
                pass
    except Exception as exc:
        out["error"] = str(exc)
        log.debug("wifi telemetry: %s", exc)
    return out


def read_battery_status(
    romeo_port: str,
    baud: int,
    *,
    use_vbat: bool | None = None,
    read_timeout: float = 1.0,
    read_idle: float = 0.12,
) -> dict[str, Any]:
    """Напряжение аккумулятора с Romeo USB (VBAT или ADC)."""
    from rpi_tools.config import ROMEO_ADC_DEFAULT_CHANNEL, battery_volts_from_adc_pin_mv
    from rpi_tools.romeo_usb import romeo_read_adc, romeo_read_vbat

    use_v = ROMEO_BATTERY_MONITOR_USE_VBAT if use_vbat is None else use_vbat
    out: dict[str, Any] = {"ok": False}
    try:
        if use_v:
            bat_mv, raw, pin_mv = romeo_read_vbat(
                romeo_port,
                baud,
                read_timeout=read_timeout,
                read_idle=read_idle,
            )
            u_fw = bat_mv / 1000.0
            out.update({
                "ok": True,
                "source": "vbat",
                "battery_v": round(battery_display_volts_to_multimeter(u_fw), 2),
                "vbat_battery_mv": bat_mv,
                "vbat_raw": raw,
                "vbat_pin_mv": pin_mv,
            })
        else:
            ch, raw, pin_mv = romeo_read_adc(
                romeo_port,
                baud,
                ROMEO_ADC_DEFAULT_CHANNEL,
                read_timeout=read_timeout,
                read_idle=read_idle,
            )
            out.update({
                "ok": True,
                "source": "adc",
                "adc_ch": ch,
                "adc_raw": raw,
                "adc_pin_mv": pin_mv,
                "battery_v": round(battery_volts_from_adc_pin_mv(pin_mv), 2),
            })
    except Exception as exc:
        out["error"] = str(exc)
        log.debug("battery telemetry: %s", exc)
    return out


def build_host_telemetry_patch(
    *,
    romeo_port: str | None,
    romeo_baud: int = 115200,
    wifi_ifname: str | None = None,
    use_vbat: bool | None = None,
) -> dict[str, Any]:
    """Словарь для PUT /rooms/.../host (плоские поля + вложенный telemetry)."""
    now_ms = int(time.time() * 1000)
    wifi = read_wifi_status(wifi_ifname)
    battery: dict[str, Any] = {"ok": False}
    if romeo_port:
        battery = read_battery_status(romeo_port, romeo_baud, use_vbat=use_vbat)

    telemetry: dict[str, Any] = {
        "at_ms": now_ms,
        "wifi": wifi,
        "battery": battery,
    }

    patch: dict[str, Any] = {
        "telemetry": telemetry,
        "telemetryAt": now_ms,
    }
    if battery.get("ok") and "battery_v" in battery:
        patch["batteryV"] = battery["battery_v"]
    if wifi.get("signal_percent") is not None:
        patch["wifiSignal"] = wifi["signal_percent"]
    if wifi.get("ssid"):
        patch["wifiSsid"] = wifi["ssid"]
    if wifi.get("rate"):
        patch["wifiRate"] = wifi["rate"]
    patch["wifiConnected"] = bool(wifi.get("connected"))
    return patch
