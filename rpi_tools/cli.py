"""Единая точка входа: argparse и вызов модулей камеры, Romeo, Wi‑Fi."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from rpi_tools.camera_stream import _default_capture_mode, run_send
from rpi_tools.errors import TcpBindError
from rpi_tools.config import (
    DISCOVERY_PORT_DEFAULT,
    JPEG_TCP_QUEUE_DEPTH_DEFAULT,
    ROMEO_ADC_DEFAULT_CHANNEL,
    ROMEO_CONTROL_PORT_DEFAULT,
    ROMEO_PIVOT_TANK_SCALE,
    ROMEO_TANK_SPEED_DEFAULT,
    ROMEO_USB_PORT,
)
from rpi_tools.logutil import setup_logging
from rpi_tools.romeo_usb import (
    run_adc_cal,
    run_adc_read,
    run_flash_romeo,
    run_serial_send,
    run_vbat_read,
)
from rpi_tools.stream_profiles import apply_stream_preset
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
        description="Raspberry Pi: камера (H.264/TCP/UDP + legacy JPEG/TCP + UDP discovery), Romeo USB, Wi‑Fi, прошивка"
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

    p_send = sub.add_parser("send", help="Стрим камеры Raspberry Pi (UDP/H.264, H.264/TCP, RTSP, legacy JPEG/TCP)")
    p_send.add_argument(
        "--host",
        default="auto",
        help="IP приёмника/ПК в LAN или auto — поиск по UDP (для udp_h264/rtp_h264 укажите IP ПК явно; для rtsp_h264 не используется)",
    )
    p_send.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Порт видеопотока: TCP/UDP порт видео или RTSP service port для rtsp_h264 (по умолчанию RTSP обычно 8554)",
    )
    p_send.add_argument("--camera", type=int, default=0, help="Индекс камеры (0 по умолчанию)")
    p_send.add_argument(
        "--width",
        type=int,
        default=1920,
        help="Ширина кадра (для custom по умолчанию 1920; preset broadcast/cinema тоже подставляют 1080p)",
    )
    p_send.add_argument("--height", type=int, default=1080, help="Высота кадра (для custom по умолчанию 1080)")
    p_send.add_argument(
        "--fps",
        type=float,
        default=30.0,
        help="Запрошенный FPS (если камера и бэкенд реально выдают)",
    )
    p_send.add_argument(
        "--jpeg-quality",
        type=int,
        default=92,
        help="Качество JPEG 1–100 (пресет broadcast подставляет 92; см. docs/pi-stream-quality.ru.md)",
    )
    p_send.add_argument(
        "--stream-preset",
        choices=["custom", "broadcast", "cinema", "mobile", "realtime"],
        default="broadcast",
        help=(
            "Готовый профиль разрешения/FPS/битрейта: broadcast (1080p30 высокий битрейт), "
            "cinema (1080p24 максимум качества), mobile (720p30 для слабее канала), "
            "realtime (960x540 для минимальной задержки). "
            "custom — только явные --width/--fps/..."
        ),
    )
    p_send.add_argument(
        "--video-mode",
        choices=["auto", "h264_tcp", "udp_h264", "rtp_h264", "rtsp_h264", "jpeg_tcp"],
        default="auto",
        help=(
            "Режим передачи видео: auto — H.264/TCP в --listen без overlay или стабильный udp_h264 при явном --host; "
            "иначе legacy JPEG/TCP; h264_tcp — аппаратный libcamera/rpicam путь через TCP listen; "
            "udp_h264 — основной операторский low-latency путь: H.264 в MPEG-TS/UDP на --host:<port>; "
            "rtp_h264 — временный alias на udp_h264, пока RTP-совместимость дорабатывается; "
            "rtsp_h264 — RTSP/H.264 server на Pi для клиентов по rtsp://<pi-ip>:<port>/<path>; "
            "jpeg_tcp — старый кастомный протокол 4 байта + JPEG."
        ),
    )
    p_send.add_argument(
        "--video-bitrate",
        type=int,
        default=40_000_000,
        metavar="BPS",
        help="Целевой битрейт для H.264 режима в бит/с (по умолчанию 40000000 = 40 Мбит/с).",
    )
    p_send.add_argument(
        "--video-intra",
        type=int,
        default=15,
        metavar="N",
        help="Интервал I-frame / IDR для H.264 режима (по умолчанию 15 кадров; меньше — быстрее recovery и ниже задержка).",
    )
    p_send.add_argument(
        "--video-profile",
        choices=["baseline", "main", "high"],
        default="high",
        help="H.264 profile для нового потока (по умолчанию high).",
    )
    p_send.add_argument(
        "--video-level",
        default=None,
        metavar="LVL",
        help="Опциональный H.264 level для системного энкодера (например 4.2).",
    )
    p_send.add_argument(
        "--rtsp-path",
        default="camera",
        help="RTSP mount path для rtsp_h264 (по умолчанию /camera).",
    )
    p_send.add_argument(
        "--jpeg-chroma",
        choices=["444", "422", "420"],
        default="422",
        help="Legacy JPEG/TCP: субдискретизация цвета JPEG: 444 — лучше края/цвет, 420 — меньше битрейт.",
    )
    p_send.add_argument(
        "--jpeg-threads",
        type=int,
        default=8,
        metavar="N",
        help="Legacy JPEG/TCP: потоки кодирования picamera2 JpegEncoder (MultiEncoder + simplejpeg).",
    )
    p_send.add_argument(
        "--no-jpeg-fast-dct",
        action="store_true",
        help="Legacy JPEG/TCP: запасной цикл capture_array использует точнее DCT в simplejpeg (медленнее).",
    )
    p_send.add_argument(
        "--legacy-picamera-jpeg-loop",
        action="store_true",
        help="Legacy JPEG/TCP: не использовать picamera2 JpegEncoder; только capture_array+JPEG (хуже FPS).",
    )
    p_send.add_argument(
        "--jpeg-tcp-queue",
        type=int,
        default=JPEG_TCP_QUEUE_DEPTH_DEFAULT,
        metavar="N",
        help=(
            "Legacy JPEG/TCP: очередь отправки JPEG по TCP (отдельный поток на Pi). "
            "По умолчанию %(default)s: кодер не блокируется, если ПК/Wi‑Fi читают медленно. "
            "0 — без очереди (весь sendall в потоке кодирования)."
        ),
    )
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
        help="Рисовать дату и время на каждом кадре; для H.264 режимов не поддерживается и форсирует legacy JPEG/TCP.",
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
        help=(
            "Захват для legacy JPEG/TCP: на Raspberry Pi по умолчанию picamera2; "
            "auto — OpenCV, при неудаче picamera2; opencv — только OpenCV. "
            "H.264 режимы используют системный rpicam/libcamera путь."
        ),
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
    p_send.add_argument(
        "--romeo-control-port",
        type=int,
        default=ROMEO_CONTROL_PORT_DEFAULT,
        metavar="PORT",
        help=(
            "При --listen: TCP-порт приёма команд Romeo с ПК по Wi‑Fi/LAN (по умолчанию %s; 0 — выключить). "
            "В ответ UDP discovery добавляется поле «control» с этим портом."
            % (ROMEO_CONTROL_PORT_DEFAULT,)
        ),
    )
    p_send.add_argument(
        "--romeo-usb",
        default=None,
        metavar="DEV",
        help=f"USB CDC Romeo для сервера управления (по умолчанию {ROMEO_USB_PORT} из rpi_tools/config.py)",
    )
    p_send.add_argument(
        "--romeo-baud",
        type=int,
        default=115200,
        help="Скорость UART Romeo для TCP→USB",
    )
    p_send.add_argument(
        "--romeo-open-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Пауза только при первом открытии USB в TCP-сессии управления (если скетч перезагружается при connect)",
    )
    p_send.add_argument(
        "--romeo-tank-speed",
        type=int,
        default=ROMEO_TANK_SPEED_DEFAULT,
        metavar="N",
        help=(
            "Базовый модуль для JSON drive left/right: на Romeo уходит TANK ±mag, mag ≈ N×"
            f"{ROMEO_PIVOT_TANK_SCALE:g} (см. rpi_tools/config ROMEO_PIVOT_TANK_SCALE). "
            "Явный JSON tank / строка «TANK l r» не масштабируются."
        ),
    )

    p_send.add_argument(
        "--romeo-turret-step",
        type=int,
        default=None,
        metavar="DEG",
        dest="romeo_turret_step",
        help=(
            "Если задано: для JSON «action\":\"turret» без поля «step» подставлять шаг в градусах "
            "(на Romeo уходит PANL 2 вместо голого PANL — мельче шаг при удержании клавиши на ПК)."
        ),
    )
    p_send.add_argument(
        "--romeo-adc-interval",
        type=float,
        default=0.0,
        metavar="SEC",
        help="При --listen: раз в SEC опрашивать канал АЦП по умолчанию (A1, см. ROMEO_ADC_DEFAULT_CHANNEL) по USB. 0 — выключить.",
    )
    p_send.add_argument(
        "--romeo-led-interval",
        type=float,
        default=5.0,
        metavar="SEC",
        help="При --listen: раз в SEC с слать на Romeo по USB команду LTG (toggle бортового светодиода). 0 — выключить.",
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

    p_adc = sub.add_parser(
        "adc-read",
        help="Romeo USB: опрос АЦП A0..A5 — одна строка «A<n> raw mV» в stdout (по умолчанию канал из config)",
    )
    p_adc.add_argument(
        "--port",
        default=ROMEO_USB_PORT,
        metavar="DEV",
        help=f"USB CDC Romeo (по умолчанию {ROMEO_USB_PORT})",
    )
    p_adc.add_argument("--baud", type=int, default=115200, help="Скорость UART")
    p_adc.add_argument(
        "--channel",
        "-c",
        type=int,
        default=ROMEO_ADC_DEFAULT_CHANNEL,
        metavar="N",
        help=f"Номер входа 0..5 (по умолчанию {ROMEO_ADC_DEFAULT_CHANNEL} — A{ROMEO_ADC_DEFAULT_CHANNEL})",
    )
    p_adc.add_argument(
        "--read-timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Максимум секунд ожидания ответа",
    )
    p_adc.add_argument(
        "--read-idle",
        type=float,
        default=0.25,
        metavar="SEC",
        help="Тишина на линии после последнего байта — ответ собран",
    )
    p_adc.add_argument(
        "--open-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Пауза после открытия порта до первой команды",
    )

    p_vbat = sub.add_parser(
        "vbat-read",
        help="Romeo USB: VBAT и battery_V с калибровкой U=a·U+b (см. ROMEO_BATTERY_CAL_* в config)",
    )
    p_vbat.add_argument(
        "--port",
        default=ROMEO_USB_PORT,
        metavar="DEV",
        help=f"USB CDC Romeo (по умолчанию {ROMEO_USB_PORT})",
    )
    p_vbat.add_argument("--baud", type=int, default=115200, help="Скорость UART")
    p_vbat.add_argument(
        "--read-timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Максимум секунд ожидания ответа",
    )
    p_vbat.add_argument(
        "--read-idle",
        type=float,
        default=0.25,
        metavar="SEC",
        help="Тишина на линии после последнего байта — ответ собран",
    )
    p_vbat.add_argument(
        "--open-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Пауза после открытия порта до первой команды",
    )

    p_cal = sub.add_parser(
        "adc-cal",
        help="Romeo USB: калибровка АЦП — VCC, VREF, VREF <mV>, VREF AUTO (текст прошивки в stdout)",
    )
    p_cal.add_argument(
        "mode",
        choices=["vcc", "vref", "vref-auto"],
        help="vcc — AVCC по bandgap; vref — запрос VREF; vref --set MV — ручной VREF; vref-auto — как VCC",
    )
    p_cal.add_argument(
        "--set",
        dest="vref_mv",
        type=int,
        default=None,
        metavar="MV",
        help="Только с mode=vref: задать опору VREF <MV> (500..7000 мВ)",
    )
    p_cal.add_argument(
        "--port",
        default=ROMEO_USB_PORT,
        metavar="DEV",
        help=f"USB CDC Romeo (по умолчанию {ROMEO_USB_PORT})",
    )
    p_cal.add_argument("--baud", type=int, default=115200, help="Скорость UART")
    p_cal.add_argument(
        "--read-timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Ожидание ответа (VCC/bandgap может быть медленным; по умолчанию 5 с)",
    )
    p_cal.add_argument(
        "--read-idle",
        type=float,
        default=0.25,
        metavar="SEC",
        help="Тишина на линии после последнего байта — ответ собран",
    )
    p_cal.add_argument(
        "--open-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Пауза после открытия порта до первой команды",
    )

    args = parser.parse_args()
    if args.cmd == "send":
        apply_stream_preset(args)
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

    if args.cmd == "adc-read":
        run_adc_read(
            args.port,
            args.baud,
            args.channel,
            args.read_timeout,
            args.read_idle,
            args.open_delay,
        )
        return 0

    if args.cmd == "vbat-read":
        run_vbat_read(
            args.port,
            args.baud,
            args.read_timeout,
            args.read_idle,
            args.open_delay,
        )
        return 0

    if args.cmd == "adc-cal":
        if args.mode == "vref" and args.vref_mv is not None:
            if not (500 <= args.vref_mv <= 7000):
                log.error("adc-cal: --set MV должно быть в диапазоне 500..7000")
                return 1
        if args.mode == "vref-auto" and args.vref_mv is not None:
            log.warning("adc-cal: --set игнорируется для vref-auto")
        run_adc_cal(
            args.port,
            args.baud,
            args.mode,
            args.vref_mv if args.mode == "vref" else None,
            args.read_timeout,
            args.read_idle,
            args.open_delay,
        )
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
                video_mode=args.video_mode,
                video_bitrate=args.video_bitrate,
                video_intra=args.video_intra,
                video_profile=args.video_profile,
                rtsp_path=args.rtsp_path,
                video_level=args.video_level,
                romeo_control_port=args.romeo_control_port,
                romeo_usb_port=args.romeo_usb,
                romeo_baud=args.romeo_baud,
                romeo_open_delay=args.romeo_open_delay,
                romeo_tank_speed=args.romeo_tank_speed,
                romeo_turret_step=args.romeo_turret_step,
                romeo_led_interval_sec=args.romeo_led_interval,
                romeo_adc_interval_sec=args.romeo_adc_interval,
                picamera_use_jpeg_encoder=not args.legacy_picamera_jpeg_loop,
                jpeg_chroma_subsampling=args.jpeg_chroma,
                jpeg_encoder_threads=args.jpeg_threads,
                jpeg_fast_dct=not args.no_jpeg_fast_dct,
                jpeg_tcp_queue_depth=args.jpeg_tcp_queue,
            )
        except TcpBindError:
            return 3
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
