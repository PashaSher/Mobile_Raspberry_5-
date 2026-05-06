"""Единая точка входа: argparse и вызов модулей камеры, Romeo, Wi‑Fi."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from rpi_tools.camera_stream import TcpBindError, _default_capture_mode, run_send
from rpi_tools.config import DISCOVERY_PORT_DEFAULT, ROMEO_USB_PORT
from rpi_tools.logutil import setup_logging
from rpi_tools.romeo_usb import run_flash_romeo, run_serial_send
from rpi_tools.wifi_connect import (
    ap_password_resolve,
    run_wifi_apply_from_file,
    run_wifi_connect,
    run_wifi_hotspot,
)
from rpi_tools.wifi_scan import run_wifi_scan

log = logging.getLogger("camstream")


def _print_hotspot_blocked_hint() -> None:
    print(
        "camstream: выход с кодом 2 — это не падение. "
        "AP не поднят: нет активного Ethernet (eth0). "
        "Подключите кабель, либо добавьте --ap-force (или wifi-hotspot --force), "
        "либо в Run and Debug выберите конфигурацию с --ap-force.",
        file=sys.stderr,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Raspberry Pi: камера (TCP MJPEG + UDP discovery), Romeo USB, Wi‑Fi, прошивка"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Логи в stderr (удобно смотреть по SSH)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Подробный вывод (-v = уровень DEBUG)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="Стрим камеры Raspberry Pi")
    p_send.add_argument(
        "--host",
        default="auto",
        help="IP приёмника в LAN или auto — поиск по UDP (приложение на ПК должно отвечать на discover)",
    )
    p_send.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP-порт приёмника (если не auto; при auto берётся из ответа discovery)",
    )
    p_send.add_argument("--camera", type=int, default=0, help="Индекс камеры (0 по умолчанию)")
    p_send.add_argument("--width", type=int, default=640)
    p_send.add_argument("--height", type=int, default=480)
    p_send.add_argument("--fps", type=float, default=25.0)
    p_send.add_argument("--jpeg-quality", type=int, default=80, help="1–100")
    p_send.add_argument(
        "--discover-port",
        type=int,
        default=DISCOVERY_PORT_DEFAULT,
        help="UDP-порт handshake (тот же, что слушает ваше приложение на ПК)",
    )
    p_send.add_argument(
        "--discover-token",
        default=None,
        help="Секрет для UDP discover (должен совпадать с клиентом на ПК)",
    )
    p_send.add_argument(
        "--discover-timeout",
        type=float,
        default=5.0,
        help="Секунд ожидания ответов за один раунд discovery",
    )
    p_send.add_argument(
        "--discover-index",
        type=int,
        default=0,
        help="Если найдено несколько ответов discover — номер в списке (0 по умолчанию)",
    )
    p_send.add_argument(
        "--discover-loop",
        action="store_true",
        help="Повторять поиск, пока по UDP не появится приёмник",
    )
    p_send.add_argument(
        "--discover-loop-interval",
        type=float,
        default=3.0,
        help="Пауза между попытками при --discover-loop",
    )
    p_send.add_argument(
        "--listen",
        action="store_true",
        help="Слушать TCP на этой машине: UDP discovery + ожидание клиента, затем камера (для автозапуска на Pi)",
    )
    p_send.add_argument(
        "--no-discovery",
        action="store_true",
        help="При --listen: не отвечать на UDP discovery (только прямой TCP по IP)",
    )
    p_send.add_argument(
        "--timestamp",
        action="store_true",
        help="Рисовать дату и время на каждом кадре (на стороне камеры, до сжатия JPEG)",
    )
    p_send.add_argument(
        "--camera-device",
        default=None,
        metavar="PATH",
        help="Явный путь V4L2, напр. /dev/video0",
    )
    p_send.add_argument(
        "--capture-backend",
        choices=["auto", "v4l2", "default"],
        default="auto",
        help="Способ открытия камеры в OpenCV (auto перебирает варианты)",
    )
    p_send.add_argument(
        "--no-set-fps",
        action="store_true",
        help="Не задавать CAP_PROP_FPS (на libcamera иногда мешает)",
    )
    p_send.add_argument(
        "--capture",
        choices=["auto", "opencv", "picamera2"],
        default=_default_capture_mode(),
        help="Захват: на Raspberry Pi по умолчанию picamera2; auto — OpenCV, при неудаче picamera2; opencv — только OpenCV",
    )
    p_send.add_argument(
        "--ap-ssid",
        default=None,
        metavar="SSID",
        help="Перед запуском send поднять на Pi Wi‑Fi точку доступа с этим SSID (например, 12345)",
    )
    p_send.add_argument(
        "--ap-password",
        default=None,
        metavar="PASS",
        help="Пароль точки доступа WPA2; иначе RPI_AP_PASSWORD или config/ap.local.env (AP_PASSWORD); иначе 12345678",
    )
    p_send.add_argument(
        "--ap-ifname",
        default=None,
        metavar="DEV",
        help="Интерфейс для точки доступа, напр. wlan0 (по умолчанию авто)",
    )
    p_send.add_argument(
        "--ap-force",
        action="store_true",
        help="Принудительно поднять AP даже без ethernet uplink (может разорвать SSH по Wi‑Fi)",
    )

    sub.add_parser("wifi-scan", help="Показать доступные Wi‑Fi сети (nmcli)")

    p_wc = sub.add_parser(
        "wifi-connect",
        help="Подключиться к Wi‑Fi и сохранить профиль (автоподключение после перезагрузки)",
    )
    p_wc.add_argument("ssid", help="Имя сети (SSID)")
    p_wc.add_argument(
        "--password",
        default=None,
        help="Пароль (в ps виден; лучше RPI_WIFI_PASSWORD или --password-file)",
    )
    p_wc.add_argument(
        "--password-file",
        default=None,
        metavar="PATH",
        help="Файл с одной строкой — пароль (права chmod 600)",
    )
    p_wc.add_argument(
        "--ifname",
        default=None,
        metavar="DEV",
        help="Интерфейс Wi‑Fi, напр. wlan0 (по умолчанию — первый wifi в nmcli)",
    )
    p_wc.add_argument(
        "--hidden",
        action="store_true",
        help="Скрытая сеть (SSID не в эфирных маяках)",
    )

    p_wa = sub.add_parser(
        "wifi-apply",
        help="Подключить Wi‑Fi из config/wifi.local.env (секреты не в git; см. wifi.local.env.example)",
    )
    p_wa.add_argument(
        "--env-file",
        default=None,
        metavar="PATH",
        help="Файл настроек (по умолчанию config/wifi.local.env в корне проекта)",
    )
    p_ap = sub.add_parser(
        "wifi-hotspot",
        help="Поднять собственную Wi‑Fi сеть (точка доступа) для подключения ПК",
    )
    p_ap.add_argument("ssid", nargs="?", default="12345", help="Имя сети (по умолчанию 12345)")
    p_ap.add_argument(
        "--password",
        default=None,
        help="Пароль WPA2 (>=8); иначе RPI_AP_PASSWORD или config/ap.local.env; иначе запасной 12345678",
    )
    p_ap.add_argument("--ifname", default=None, metavar="DEV", help="Интерфейс Wi‑Fi, напр. wlan0")
    p_ap.add_argument(
        "--force",
        action="store_true",
        help="Принудительно поднять AP без проверки ethernet uplink (может разорвать SSH по Wi‑Fi)",
    )

    p_flash = sub.add_parser(
        "flash-romeo",
        help="Прошить Romeo/Leonardo (ATmega32U4) по USB — см. rpi_tools/romeo_usb.py и scripts/",
    )
    p_flash.add_argument(
        "--hex",
        default=os.path.expanduser("~/firmware.hex"),
        metavar="PATH",
        help="Путь к firmware.hex (по умолчанию ~/firmware.hex)",
    )

    p_ser = sub.add_parser(
        "serial-send",
        aliases=["romeo"],
        help="Romeo USB: по умолчанию «?»+LF, 115200; ответ в stdout (синоним: romeo)",
        description=(
            "Команды моторов/серво по текстовому протоколу прошивки. "
            "Порт USB по умолчанию — ROMEO_USB_PORT в rpi_tools/config.py. Логи — в stderr."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_ser.add_argument(
        "--port",
        default=ROMEO_USB_PORT,
        metavar="DEV",
        help=f"USB CDC Romeo (по умолчанию {ROMEO_USB_PORT}; константа ROMEO_USB_PORT в rpi_tools/config.py)",
    )
    p_ser.add_argument("--baud", type=int, default=115200, help="Скорость UART (часто 9600 или 115200)")
    p_ser.add_argument("--text", default="?", help="Строка UTF-8 для отправки")
    p_ser.add_argument(
        "-n",
        "--nl",
        action="store_true",
        help="Необязательно: перевод строки \\n уже добавляется по умолчанию",
    )
    p_ser.add_argument(
        "--no-nl",
        action="store_true",
        help="Не добавлять \\n в конец (сырая строка/один символ без LF)",
    )
    p_ser.add_argument(
        "--read-timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Максимум секунд ожидания любых байт ответа (по умолчанию 3)",
    )
    p_ser.add_argument(
        "--read-idle",
        type=float,
        default=0.25,
        metavar="SEC",
        help="Тишина на линии после последнего байта — ответ собран (по умолчанию 0.25)",
    )
    p_ser.add_argument(
        "--open-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Пауза после открытия USB-порта до отправки (часто 1.5–2 с: плата успевает выйти из reset)",
    )

    args = parser.parse_args()
    level = logging.DEBUG if args.verbose else getattr(logging, args.log_level)
    setup_logging(level)
    log.info("camstream: команда=%s, уровень логов=%s", args.cmd, logging.getLevelName(level))

    if args.cmd == "wifi-scan":
        run_wifi_scan()
        return 0

    if args.cmd == "wifi-connect":
        run_wifi_connect(
            args.ssid,
            args.password,
            args.password_file,
            args.ifname,
            args.hidden,
        )
        return 0

    if args.cmd == "wifi-apply":
        run_wifi_apply_from_file(args.env_file)
        return 0

    if args.cmd == "wifi-hotspot":
        ap_rc = run_wifi_hotspot(
            args.ssid,
            ap_password_resolve(args.password),
            args.ifname,
            require_ethernet_uplink=not args.force,
        )
        if ap_rc == 2:
            _print_hotspot_blocked_hint()
        return ap_rc

    if args.cmd == "flash-romeo":
        run_flash_romeo(args.hex)
        return 0

    if args.cmd in ("serial-send", "romeo"):
        append_lf = not args.no_nl
        run_serial_send(
            args.port,
            args.baud,
            args.text,
            append_lf,
            args.read_timeout,
            args.read_idle,
            args.open_delay,
        )
        return 0

    if args.cmd == "send":
        if args.ap_ssid:
            ap_rc = run_wifi_hotspot(
                args.ap_ssid,
                ap_password_resolve(args.ap_password),
                args.ap_ifname,
                require_ethernet_uplink=not args.ap_force,
            )
            if ap_rc == 2:
                _print_hotspot_blocked_hint()
            if ap_rc != 0:
                return ap_rc
        if args.listen and args.host.strip().lower() not in ("auto", "discover"):
            print(
                "При --listen параметр --host не используется (клиенты подключаются к этому Pi).",
                file=sys.stderr,
            )
        if args.listen:
            listen_disc = None if args.no_discovery or args.discover_port == 0 else args.discover_port
        else:
            listen_disc = None
        try:
            run_send(
                args.host,
                args.port,
                args.camera,
                args.width,
                args.height,
                args.fps,
                args.jpeg_quality,
                args.discover_port,
                args.discover_token,
                args.discover_timeout,
                args.discover_index,
                args.discover_loop,
                args.discover_loop_interval,
                args.listen,
                listen_disc,
                None,
                args.timestamp,
                args.camera_device,
                args.capture_backend,
                not args.no_set_fps,
                args.capture,
            )
        except TcpBindError:
            return 3
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
