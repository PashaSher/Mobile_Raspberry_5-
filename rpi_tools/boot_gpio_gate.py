#!/usr/bin/env python3
"""
Запуск по состоянию GPIO при старте Raspberry Pi.

- Пин в режиме **вход, подтяжка вверх** (pull-up): в покое высокий уровень.
- Если вход **замкнут на землю** (низкий уровень) — немедленно ``exec`` команды после ``--``.
  В gpiozero при ``pull_up=True`` это ``DigitalInputDevice.is_active is True`` (не ``value==0``).
- Если **не замкнут** — выход без запуска (код 0).

Пины в нумерации **BCM** (как в Pinout Raspberry Pi).

Переменная окружения ``CAMSTREAM_BOOT_GPIO_BCM`` задаёт номер BCM, если не передан ``--bcm``.
Если ни env, ни ``--bcm`` не заданы — **сквозной запуск** (выполняется команда всегда, проверки GPIO нет).

Лог в файл: ``CAMSTREAM_BOOT_LOG`` (путь), иначе ``~/.local/share/camstream/camstream_boot.log`` — дублирует ключевые сообщения из stderr.

Если gate выходит **без** ``exec`` (приложение не запущено), создаётся маркер-файл (см. ``CAMSTREAM_GATE_SKIP_MARKER``) —
обёртка ``scripts/camstream-gpio-wifi-fallback.sh`` может по нему поднять домашний Wi‑Fi. Перед ``exec`` маркер удаляется.

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


def _boot_log_path() -> str:
    p = os.environ.get("CAMSTREAM_BOOT_LOG", "").strip()
    if p:
        return os.path.expanduser(p)
    return os.path.expanduser("~/.local/share/camstream/camstream_boot.log")


def _emit(msg: str) -> None:
    """Строка в stderr + дозапись в файл (для разбора после перезагрузки, если journal мало)."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} boot_gpio_gate: {msg}\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    path = _boot_log_path()
    try:
        base = os.path.dirname(path)
        if base:
            os.makedirs(base, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        sys.stderr.write(f"{ts} boot_gpio_gate: не записал лог в {path!r}: {exc}\n")


def _skip_marker_path() -> str:
    p = os.environ.get("CAMSTREAM_GATE_SKIP_MARKER", "").strip()
    if p:
        return os.path.expanduser(p)
    return f"/tmp/camstream-gpio-no-launch.{os.getuid()}"


def _mark_skip() -> None:
    path = _skip_marker_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("1\n")
    except OSError as exc:
        _emit(f"не записал маркер пропуска {path!r}: {exc}")


def _clear_skip_marker() -> None:
    path = _skip_marker_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


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
        "--wait-ground-sec",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Сколько секунд опрашивать пин: запуск при появлении низкого уровня (GND). "
        "0 — один раз прочитать и выйти, если уже не LOW.",
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
        _emit("после '--' нужна команда, например: -- python stream_camera.py send --listen …")
        return 2

    _emit(
        f"старт pid={os.getpid()} argv={sys.argv!r} log_file={_boot_log_path()!r} "
        f"stable_ms={args.stable_ms} wait_ground_sec={args.wait_ground_sec} invert={args.invert}"
    )

    bcm = args.bcm
    if bcm is None:
        raw = os.environ.get("CAMSTREAM_BOOT_GPIO_BCM", "").strip()
        if raw:
            try:
                bcm = int(raw)
            except ValueError:
                _emit(f"CAMSTREAM_BOOT_GPIO_BCM={raw!r} не число")
                return 2

    if bcm is None:
        _emit("GPIO gate отключён (нет --bcm и CAMSTREAM_BOOT_GPIO_BCM) — exec без проверки пина")
        _clear_skip_marker()
        os.execvp(remainder[0], remainder)

    try:
        from gpiozero import DigitalInputDevice
    except ImportError:
        _emit(
            "нужен пакет gpiozero: pip install gpiozero "
            "(или apt install python3-gpiozero на Raspberry Pi OS)"
        )
        return 1

    pin = DigitalInputDevice(bcm, pull_up=True)
    try:
        if args.stable_ms > 0:
            time.sleep(args.stable_ms / 1000.0)

        wait_sec = max(0.0, float(args.wait_ground_sec))
        deadline = time.monotonic() + wait_sec if wait_sec > 0 else None
        poll = 0.15

        if deadline is not None:
            _emit(f"BCM {bcm} — жду замыкания на GND (до {wait_sec:.0f} с), затем запуск приложения.")

        first_sample = True
        last_status_log = time.monotonic()

        while True:
            # gpiozero + pull_up=True: замыкание на GND задаёт активное состояние (electrical LOW),
            # тогда ``is_active`` и ``value`` трактуют как 1 — НЕ сырое «0 на линии».
            to_gnd = pin.is_active
            launch = to_gnd if not args.invert else not to_gnd
            if first_sample:
                _emit(
                    f"первая выборка BCM {bcm}: is_active={pin.is_active} value={getattr(pin, 'value', '?')} "
                    f"invert={args.invert} → launch={launch}"
                )
                first_sample = False
            elif deadline is not None and (time.monotonic() - last_status_log) >= 30.0:
                _emit(
                    f"ещё жду GND BCM {bcm}: is_active={pin.is_active} value={getattr(pin, 'value', '?')}"
                )
                last_status_log = time.monotonic()

            if launch:
                _emit(f"BCM {bcm}, линия к GND (активно) — exec {remainder}")
                _clear_skip_marker()
                os.execvp(remainder[0], remainder)

            if deadline is None:
                break
            if time.monotonic() >= deadline:
                _emit(f"BCM {bcm}: за {wait_sec:.0f} с пин так и не на земле — выход без запуска.")
                _mark_skip()
                return 0
            time.sleep(poll)

        lvl = "к GND" if pin.is_active else "не на земле"
        _emit(
            f"BCM {bcm}, сейчас {lvl} — запуск отменён (нет --wait-ground-sec; см. например --wait-ground-sec 45)."
        )
        _mark_skip()
        return 0
    finally:
        try:
            pin.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
