"""Сканирование Wi‑Fi через nmcli (NetworkManager)."""

from __future__ import annotations

import logging
import subprocess
import sys

log = logging.getLogger("camstream")


def run_wifi_scan() -> None:
    log.info("wifi-scan: запуск nmcli ...")
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except FileNotFoundError:
        log.error("nmcli не найден. Установите NetworkManager или подключайтесь к Wi‑Fi вручную.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("Таймаут сканирования Wi‑Fi.")
        sys.exit(1)
    if r.returncode != 0:
        log.error("nmcli: %s", r.stderr or "ошибка")
        sys.exit(1)
    lines = [ln for ln in r.stdout.strip().splitlines() if ln.strip()]
    if not lines:
        log.warning("Сетей не найдено (возможно, Wi‑Fi выключён).")
        return
    log.info("SSID : SIGNAL : SECURITY (nmcli)")
    for ln in lines:
        log.info("%s", ln)
