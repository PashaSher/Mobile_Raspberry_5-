"""Единая точка входа: argparse и вызов модулей камеры, Romeo, Wi‑Fi."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

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

_FIREBASE_ENV_HINT_RU = (
    "Подставить пути из переменных окружения не удалось (часто пустой результат от ${env:…} при отладке). "
    "Создайте config/firebase.debug.env из config/firebase.debug.env.example "
    "(или выполните scripts/ensure_firebase_debug_env.sh) и выберите в launch.json envFile этот файл."
)


def _firebase_cred_existing_path(raw: str) -> str:
    """Не пустая строка, файл JSON ключа Firebase существует."""
    s = (raw or "").strip()
    if not s:
        raise argparse.ArgumentTypeError(
            "--firebase-cred не может быть пустым.\n"
            + _FIREBASE_ENV_HINT_RU
        )
    path = Path(s).expanduser()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Файл ключа не найден или не файл: {path}")
    return str(path.resolve())


def _firebase_rtdb_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        raise argparse.ArgumentTypeError(
            "--firebase-db-url не может быть пустым.\n" + _FIREBASE_ENV_HINT_RU
        )
    low = u.lower()
    if not low.startswith("https://"):
        raise argparse.ArgumentTypeError("URL базы данных должен начинаться с https://")
    if "firestore.googleapis.com" in low or "firebasestorage.googleapis.com" in low:
        raise argparse.ArgumentTypeError(
            "Похоже на Firestore или Storage URL; для WebRTC нужен Realtime Database."
        )
    if "firebaseio.com" not in low and "firebasedatabase.app" not in low:
        raise argparse.ArgumentTypeError(
            "Ожидается узел вида *.firebaseio.com или *.firebasedatabase.app "
            "(Realtime Database)."
        )
    return u.rstrip("/")


def _webrtc_room_non_empty(raw: str) -> str:
    rid = (raw or "").strip()
    if not rid:
        raise argparse.ArgumentTypeError(
            "--room не может быть пустым "
            '(пустая строка сбросит имя комнаты; omit --room и будет "pi-camera").'
        )
    return rid


def _print_hotspot_blocked_hint() -> None:
    print(
        "camstream: выход с кодом 2 — это не падение. "
        "AP не поднят: нет активного Ethernet (eth0). "
        "Подключите кабель, либо добавьте --ap-force (или wifi-hotspot --force), "
        "либо в Run and Debug выберите конфигурацию с --ap-force.",
        file=sys.stderr,
    )


class ArgparseCliExit(Exception):
    """Подмена argparse exit(): не вызывать sys.exit (ломает отладчик/pydevd на Python 3.13)."""

    __slots__ = ("code",)

    def __init__(self, code: int | None = 0) -> None:
        self.code = code


class CamstreamArgumentParser(argparse.ArgumentParser):
    """Все подкоманды с exit_on_error=False; help/ошибки через ArgparseCliExit или ArgumentError."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("exit_on_error", False)
        super().__init__(*args, **kwargs)

    def exit(self, status: int = 0, message: str | None = None) -> None:  # noqa: A003 (argparse API)
        if message:
            self._print_message(message, sys.stderr)
        raise ArgparseCliExit(status)


def _print_usage_chain_for_cli_error(main_parser: argparse.ArgumentParser, argv: list[str]) -> None:
    """Как «usage» в stderr у argparse.error, плюс usage подкоманды по argv (если нашли)."""
    main_parser.print_usage(sys.stderr)
    sub_action = None
    for action in getattr(main_parser, "_actions", []):
        if action.__class__.__name__ == "_SubParsersAction":
            sub_action = action
            break
    if sub_action is None:
        return
    name_map = getattr(sub_action, "_name_parser_map", {})
    for tok in argv[1:]:
        if tok.startswith("-"):
            continue
        if tok in name_map:
            try:
                name_map[tok].print_usage(sys.stderr)
            except Exception:
                pass
            break


def main() -> int:
    parser = CamstreamArgumentParser(
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

    p_webrtc = sub.add_parser(
        "webrtc",
        help="WebRTC Host: H.264 видео + Data Channel управление через Firebase signaling",
    )
    p_webrtc.add_argument(
        "--firebase-cred",
        required=True,
        metavar="PATH",
        type=_firebase_cred_existing_path,
        help="Путь к serviceAccountKey.json от Firebase",
    )
    p_webrtc.add_argument(
        "--firebase-db-url",
        required=True,
        metavar="URL",
        type=_firebase_rtdb_url,
        help=(
            "URL Firebase Realtime Database, "
            "например https://<id>-default-rtdb.firebaseio.com (подобрать: команда firebase-probe)"
        ),
    )
    p_webrtc.add_argument(
        "--room",
        default="pi-camera",
        metavar="ID",
        type=_webrtc_room_non_empty,
        help=(
            "Имя комнаты в RTDB (/rooms/<id>/). То же строкой в HTML оператора; "
            "если браузер пишет в pi-cam-2 — запуск: --room pi-cam-2"
        ),
    )
    p_webrtc.add_argument("--width", type=int, default=1280, help="Ширина кадра (по умолчанию 1280)")
    p_webrtc.add_argument("--height", type=int, default=720, help="Высота кадра (по умолчанию 720)")
    p_webrtc.add_argument("--fps", type=float, default=30.0, help="FPS (по умолчанию 30)")
    p_webrtc.add_argument(
        "--video-bitrate",
        type=int,
        default=4_000_000,
        metavar="BPS",
        help="Битрейт H.264 в бит/с (по умолчанию 4000000 = 4 Мбит/с)",
    )
    p_webrtc.add_argument(
        "--video-intra",
        type=int,
        default=30,
        metavar="N",
        help="Интервал I-frame / IDR (по умолчанию 30)",
    )
    p_webrtc.add_argument(
        "--video-profile",
        choices=["baseline", "main", "high"],
        default="baseline",
        help=(
            "H.264 профиль для rpicam перед RTP (по умолчанию baseline — лучше с декодерами браузера)"
        ),
    )
    p_webrtc.add_argument(
        "--romeo-usb",
        default=None,
        metavar="DEV",
        help=f"USB CDC Romeo (по умолчанию {ROMEO_USB_PORT})",
    )
    p_webrtc.add_argument("--romeo-baud", type=int, default=115200, help="Скорость UART Romeo")
    p_webrtc.add_argument(
        "--romeo-tank-speed",
        type=int,
        default=ROMEO_TANK_SPEED_DEFAULT,
        metavar="N",
        help="Базовый модуль для JSON drive left/right",
    )
    p_webrtc.add_argument(
        "--romeo-turret-step",
        type=int,
        default=None,
        metavar="DEG",
        help="Шаг башни по умолчанию для action=turret",
    )
    p_webrtc.add_argument(
        "--room-only",
        action="store_true",
        dest="webrtc_room_only",
        help=(
            "Только записать в RTDB /rooms/<--room>/status=waiting и выйти "
            "(без камеры и aiortc; проверить cred и --firebase-db-url на Pi)"
        ),
    )
    # Глобальный -v задаётся *до* подкоманды; дубль здесь — чтобы работало ``webrtc … -v`` (типично в Run/Debug).
    p_webrtc.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        dest="webrtc_verbose",
        help=(
            "Усилить логирование до DEBUG (суммируется с общим ``-v``, если он перед webrtc)"
        ),
    )

    p_fb_probe = sub.add_parser(
        "firebase-probe",
        help="Подобрать Firebase Realtime Database URL и проверить запись в rooms/<id> (диагностика WebRTC signaling)",
    )
    p_fb_probe.add_argument(
        "--firebase-cred",
        required=True,
        metavar="PATH",
        dest="firebase_cred_probe",
        type=_firebase_cred_existing_path,
        help="serviceAccountKey.json (тот же файл, что для webrtc)",
    )
    p_fb_probe.add_argument(
        "--room",
        default="pi-camera",
        metavar="ID",
        dest="firebase_room_probe",
        help="Имя комнаты для тестовой записи (по умолчанию pi-camera)",
    )
    p_fb_probe.add_argument(
        "--firebase-db-url",
        default=None,
        metavar="URL",
        dest="firebase_db_url_override",
        help="Проверить только этот URL (без перебора регионов)",
    )

    try:
        args = parser.parse_args()
    except ArgparseCliExit as cli_ex:
        c = cli_ex.code
        if c is None:
            return 0
        if isinstance(c, int):
            return c
        return 1
    except argparse.ArgumentError as exc:
        _print_usage_chain_for_cli_error(parser, sys.argv)
        print(f"{parser.prog}: error: {exc}\n", file=sys.stderr, end="")
        return 2

    if args.cmd == "send":
        apply_stream_preset(args)

    # Ранняя диагностика без лишних строк camstream INFO
    if args.cmd == "firebase-probe":
        from rpi_tools.firebase_probe import run_firebase_rtdb_probe

        return run_firebase_rtdb_probe(
            args.firebase_cred_probe,
            args.firebase_room_probe,
            database_url_override=args.firebase_db_url_override,
        )

    _vv = args.verbose + getattr(args, "webrtc_verbose", 0)
    level = logging.DEBUG if _vv else getattr(logging, args.log_level)
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

    if args.cmd == "webrtc":
        import asyncio

        if args.webrtc_room_only:

            async def _webrtc_room_only() -> None:
                from rpi_tools.webrtc_signaling import FirebaseSignaling, init_firebase

                init_firebase(args.firebase_cred, args.firebase_db_url)
                await FirebaseSignaling(args.room).create_room()

            try:
                asyncio.run(_webrtc_room_only())
            except Exception:
                log.exception(
                    "webrtc --room-only: запись комнаты не удалась "
                    "(см. выше; сравните URL с результатом firebase-probe)"
                )
                return 1
            log.info(
                "webrtc --room-only: ок. В Firebase Console откройте Realtime Database и узел rooms/%s",
                args.room,
            )
            return 0

        try:
            from rpi_tools.camera_stream import _CameraControlState, _make_camera_control_handler
            from rpi_tools.webrtc_host import run_webrtc_host
            from rpi_tools.romeo_usb import romeo_exchange
        except ModuleNotFoundError as e:
            mod = getattr(e, "name", "") or ""
            pip_hint = "`pip install -r requirements.txt` — полный список для Pi/WebRTC/Firebase."
            if mod == "firebase_admin":
                pip_hint = (
                    "`pip install firebase-admin` (пакет импортируется как firebase_admin) "
                    "или `pip install -r requirements.txt`."
                )
            elif mod in ("aiortc", "av"):
                pip_hint = "`pip install aiortc av` или `pip install -r requirements.txt`."
            log.error(
                "Для режима «webrtc» не установлен модуль %r (%s). "
                "Выберите интерпретатор того venv, где стоят зависимости (часто ./.venv/bin/python), затем: %s",
                mod,
                e,
                pip_hint,
            )
            print(
                "camstream: нет модуля для webrtc. В Cursor: выберите интерпретатор .venv проекта "
                "и выполните: pip install -r requirements.txt",
                file=sys.stderr,
            )
            return 1

        camera_state = _CameraControlState()
        camera_handler = _make_camera_control_handler(camera_state)

        romeo_usb = args.romeo_usb or ROMEO_USB_PORT
        romeo_baud = args.romeo_baud
        tank_speed = args.romeo_tank_speed
        turret_step = args.romeo_turret_step

        def _webrtc_command_handler(obj: dict) -> dict:
            cam_result = camera_handler(obj)
            if cam_result is not None:
                return cam_result
            from rpi_tools.romeo_control_server import _json_to_romeo_lines
            try:
                lines = _json_to_romeo_lines(obj, tank_speed, turret_step)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
            parts: list[str] = []
            for cmd_line in lines:
                try:
                    chunk = romeo_exchange(
                        romeo_usb, romeo_baud, cmd_line,
                        append_lf=True, read_timeout=0.45, read_idle=0.03,
                    )
                    if chunk:
                        parts.append(chunk.decode("utf-8", errors="replace"))
                except (OSError, RuntimeError) as e:
                    return {"ok": False, "error": str(e)}
            return {"ok": True, "reply": "".join(parts)}

        camera_extra = camera_state.build_rpicam_args()

        try:
            asyncio.run(run_webrtc_host(
                firebase_cred=args.firebase_cred,
                firebase_db_url=args.firebase_db_url,
                room_id=args.room,
                width=args.width,
                height=args.height,
                fps=args.fps,
                bitrate=args.video_bitrate,
                intra=args.video_intra,
                profile=args.video_profile,
                camera_extra_args=camera_extra,
                command_handler=_webrtc_command_handler,
            ))
        except KeyboardInterrupt:
            log.info("webrtc: остановка по Ctrl+C")
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
