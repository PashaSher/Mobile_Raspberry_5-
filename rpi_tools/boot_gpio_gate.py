#!/usr/bin/env python3
"""
Запуск по состоянию GPIO при старте Raspberry Pi.

- Пин в режиме **вход, подтяжка вверх** (pull-up): в покое высокий уровень.
- Если вход **замкнут на землю** (низкий уровень) — немедленно ``exec`` команды после ``--``.
- Если **не замкнут** — выход без запуска (код 0).

Пины в нумерации **BCM** (как в Pinout Raspberry Pi).

Переменная окружения ``CAMSTREAM_BOOT_GPIO_BCM`` задаёт номер BCM, если не передан ``--bcm``.
Если ни env, ни ``--bcm`` не заданы — **сквозной запуск** (выполняется команда всегда, проверки GPIO нет).

Зависимость: ``pip install gpiozero`` (на Raspberry Pi OS обычно есть в репозитории).

Пример::

    export CAMSTREAM_BOOT_GPIO_BCM=17
    python -m rpi_tools.boot_gpio_gate -- python stream_camera.py send --listen ...

Или systemd (см. ``scripts/camstream-gpio-gate.service.example``).
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="GPIO pull-up gate: если низкий уровень — exec команды после --")
    parser.add_argument(
        "--bcm",
        type=int,
        default=None,
        metavar="N",
        help="Номер GPIO в BCM (иначе переменная CAMSTREAM_BOOT_GPIO_BCM; если нигде не задано — gate отключён, всегда exec)",
    )
    parser.add_argument(
        "--stable-ms",
        type=float,
        default=80.0,
        metavar="MS",
        help="Пауза после настройке пина и перед чтением (мс)",
    )
    parser.add_argument(
        "--invert",
        action="store_true",
        help="Инвертировать логику: запуск при высоком уровне (редко нужно)",
    )
    parser.add_argument(
        "remainder",
        nargs=argparse.REMAINDER,
        help="После маркера --: команда и аргументы",
    )
    args = parser.parse_args()

    remainder = args.remainder
    if remainder and remainder[0] == "--":
        remainder = remainder[1:]
    if not remainder:
        print("boot_gpio_gate: после '--' нужна команда, например: -- python stream_camera.py send --listen …", file=sys.stderr)
        return 2

    bcm = args.bcm
    if bcm is None:
        raw = os.environ.get("CAMSTREAM_BOOT_GPIO_BCM", "").strip()
        if raw:
            try:
                bcm = int(raw)
            except ValueError:
                print(f"boot_gpio_gate: CAMSTREAM_BOOT_GPIO_BCM={raw!r} не число", file=sys.stderr)
                return 2

    if bcm is None:
        os.execvp(remainder[0], remainder)

    try:
        from gpiozero import DigitalInputDevice
    except ImportError:
        print(
            "boot_gpio_gate: нужен пакет gpiozero: pip install gpiozero "
            "(или apt install python3-gpiozero на Raspberry Pi OS)",
            file=sys.stderr,
        )
        return 1

    pin = DigitalInputDevice(bcm, pull_up=True)
    try:
        if args.stable_ms > 0:
            time.sleep(args.stable_ms / 1000.0)

        grounded = pin.value == 0
        launch = grounded if not args.invert else not grounded

        if launch:
            os.execvp(remainder[0], remainder)
        return 0
    finally:
        try:
            pin.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
