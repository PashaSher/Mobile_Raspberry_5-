"""Сохранённое подключение Wi‑Fi через NetworkManager (nmcli)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger("camstream")


def _nm_run(args: list[str], *, sudo: bool, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    cmd = ["sudo", *args] if sudo else args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _wifi_device(ifname: str | None) -> str:
    if ifname:
        return ifname
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "wlan0"
    if r.returncode != 0:
        return "wlan0"
    for line in r.stdout.splitlines():
        if ":" not in line:
            continue
        dev, typ = line.split(":", 1)
        if typ.strip() == "wifi":
            return dev.strip()
    return "wlan0"


def _active_wifi_profile_name(device: str) -> str | None:
    r = subprocess.run(
        ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", device],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        return None
    name = (r.stdout or "").strip()
    return name or None


def _nm_connection_names_for_ssid(ssid: str) -> list[str]:
    """Имена сохранённых профилей NM, у которых SSID совпадает с запрошенным."""
    r = subprocess.run(
        ["nmcli", "-t", "-f", "NAME", "connection", "show"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if r.returncode != 0:
        return []
    out: list[str] = []
    for raw in r.stdout.splitlines():
        name = raw.strip()
        if not name:
            continue
        r2 = subprocess.run(
            ["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", name],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if r2.returncode != 0:
            continue
        if (r2.stdout or "").strip() == ssid:
            out.append(name)
    return out


def _nm_set_autoconnect(prof: str, *, sudo: bool) -> None:
    _nm_run(
        ["nmcli", "connection", "modify", prof, "connection.autoconnect", "yes"],
        sudo=sudo,
        timeout=15,
    )
    _nm_run(
        ["nmcli", "connection", "modify", prof, "connection.autoconnect-priority", "100"],
        sudo=sudo,
        timeout=15,
    )


def _wifi_connect_via_profile(
    ssid: str,
    pwd: str,
    dev: str,
    ifname: str | None,
    *,
    sudo: bool,
) -> tuple[bool, str]:
    """
    Обновляет PSK у существующего профиля или создаёт новый; поднимает соединение.
    Возвращает (успех, текст stderr/stdout для лога).
    """
    names = _nm_connection_names_for_ssid(ssid)
    if not names:
        con_name = ssid.replace(" ", "-")[:80] or "wifi-profile"
        add_cmd = [
            "nmcli",
            "connection",
            "add",
            "type",
            "wifi",
            "con-name",
            con_name,
            "ssid",
            ssid,
            "802-11-wireless-security.key-mgmt",
            "wpa-psk",
            "802-11-wireless-security.psk",
            pwd,
        ]
        if ifname:
            add_cmd += ["ifname", ifname]
        r_add = _nm_run(add_cmd, sudo=sudo, timeout=60)
        if r_add.returncode != 0:
            return False, (r_add.stderr or r_add.stdout or "").strip()
        prof = con_name
    else:
        prof = names[0]
        r_mod = _nm_run(
            [
                "nmcli",
                "connection",
                "modify",
                prof,
                "802-11-wireless-security.key-mgmt",
                "wpa-psk",
                "802-11-wireless-security.psk",
                pwd,
            ],
            sudo=sudo,
            timeout=30,
        )
        if r_mod.returncode != 0:
            return False, (r_mod.stderr or r_mod.stdout or "").strip()

    up_cmd = ["nmcli", "connection", "up", prof]
    if ifname:
        up_cmd += ["ifname", ifname]
    r_up = _nm_run(up_cmd, sudo=sudo, timeout=90)
    if r_up.returncode != 0:
        return False, (r_up.stderr or r_up.stdout or "").strip()

    _nm_set_autoconnect(prof, sudo=sudo)
    return True, (r_up.stdout or "").strip()


def run_wifi_connect(
    ssid: str,
    password: str | None,
    password_file: str | None,
    ifname: str | None,
    hidden: bool,
) -> None:
    """
    Подключается к сети и оставляет профиль в NetworkManager (переживает перезагрузку).

    Пароль лучше не светить в списке процессов: ``export RPI_WIFI_PASSWORD=...`` или ``--password-file``.
    """
    pwd = password
    if pwd is None and password_file:
        try:
            with open(os.path.expanduser(password_file), encoding="utf-8") as f:
                pwd = f.readline().strip()
        except OSError as e:
            log.error("Не удалось прочитать --password-file: %s", e)
            sys.exit(1)
    if pwd is None:
        pwd = os.environ.get("RPI_WIFI_PASSWORD") or os.environ.get("WIFI_PASSWORD")
    if not pwd:
        log.error(
            "Нужен пароль: --password, --password-file путь, либо переменная RPI_WIFI_PASSWORD (или WIFI_PASSWORD)"
        )
        sys.exit(1)

    dev = _wifi_device(ifname)
    cmd: list[str] = ["nmcli", "device", "wifi", "connect", ssid, "password", pwd]
    if ifname:
        cmd += ["ifname", ifname]
    if hidden:
        cmd += ["hidden", "yes"]

    log.info("wifi-connect: сеть «%s», интерфейс %s", ssid, dev)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except FileNotFoundError:
        log.error("nmcli не найден (нужен NetworkManager, как на Raspberry Pi OS).")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("Таймаут подключения к Wi‑Fi.")
        sys.exit(1)

    err = (r.stderr or r.stdout or "").strip()
    use_fallback = r.returncode != 0 and (
        "key-mgmt" in err.lower()
        or "property is missing" in err.lower()
        or "not authorized" in err.lower()
    )

    if r.returncode == 0:
        msg = (r.stdout or r.stderr or "").strip()
        if msg:
            log.info("%s", msg)
    elif use_fallback:
        log.warning("nmcli wifi connect не сработал (%s), пробуем профиль NM (modify + up) …", err[:200])
        ok = False
        msg = ""
        for sudo in (False, True):
            ok, msg = _wifi_connect_via_profile(ssid, pwd, dev, ifname, sudo=sudo)
            if ok:
                if msg:
                    log.info("%s", msg)
                break
            if sudo is False and ("not authorized" in msg.lower() or "permission" in msg.lower()):
                log.info("нужны права root для NM — повтор с sudo …")
        if not ok:
            log.error("Подключение не удалось: %s", msg or "nmcli error")
            sys.exit(1)
    else:
        log.error("Подключение не удалось: %s", err or "nmcli error")
        sys.exit(1)

    prof = _active_wifi_profile_name(dev)
    if prof:
        _nm_set_autoconnect(prof, sudo=False)
        r2 = subprocess.run(
            ["nmcli", "connection", "modify", prof, "connection.autoconnect", "yes"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r2.returncode != 0:
            _nm_run(["nmcli", "connection", "modify", prof, "connection.autoconnect", "yes"], sudo=True, timeout=10)
            _nm_run(
                ["nmcli", "connection", "modify", prof, "connection.autoconnect-priority", "100"],
                sudo=True,
                timeout=10,
            )
        else:
            subprocess.run(
                ["nmcli", "connection", "modify", prof, "connection.autoconnect-priority", "100"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        log.info("Профиль «%s» сохранён: autoconnect=yes (после перезагрузки сеть поднимется сама).", prof)
    else:
        log.warning(
            "Не удалось определить имя профиля NM. Проверьте: nmcli connection show --active; "
            "вручную: nmcli connection modify <имя> connection.autoconnect yes"
        )


def ap_password_resolve(explicit: str | None, env_file: str | None = None) -> str | None:
    """
    Пароль точки доступа: аргумент CLI > RPI_AP_PASSWORD > config/ap.local.env (ключ AP_PASSWORD).
    Возвращает None, если нигде не задано — тогда hotspot подставит запасной пароль 12345678.
    """
    if explicit:
        s = explicit.strip()
        return s or None
    env_var = (os.environ.get("RPI_AP_PASSWORD") or "").strip()
    if env_var:
        return env_var
    from rpi_tools.config import PROJECT_ROOT

    path = env_file or os.path.join(PROJECT_ROOT, "config", "ap.local.env")
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        return None
    data = _parse_simple_env(path)
    p = (data.get("AP_PASSWORD") or "").strip()
    return p or None


def _parse_simple_env(path: str) -> dict[str, str]:
    """Строки KEY=VALUE (без bash); комментарии от # до конца строки. Значение может содержать =."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
                v = v[1:-1]
            if k:
                out[k] = v
    return out


def run_wifi_apply_from_file(env_path: str | None = None) -> None:
    """Читает ``config/wifi.local.env`` и вызывает ``run_wifi_connect`` (профиль NM с autoconnect)."""
    from rpi_tools.config import PROJECT_ROOT

    path = env_path or os.path.join(PROJECT_ROOT, "config", "wifi.local.env")
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        log.error(
            "Нет файла %s. Скопируйте шаблон: cp config/wifi.local.env.example config/wifi.local.env",
            path,
        )
        sys.exit(1)
    data = _parse_simple_env(path)
    ssid = (data.get("WIFI_SSID") or "").strip()
    if not ssid:
        log.error("В %s задайте WIFI_SSID=имя_сети", path)
        sys.exit(1)
    pwd_raw = data.get("WIFI_PASSWORD")
    pwd = (pwd_raw.strip() if pwd_raw else None) or None
    pwfile = (data.get("WIFI_PASSWORD_FILE") or "").strip() or None
    if pwfile:
        pwfile = os.path.expanduser(pwfile)
    if not pwd and not pwfile:
        log.error("В %s укажите WIFI_PASSWORD=... или WIFI_PASSWORD_FILE=путь_к_файлу_одной_строки", path)
        sys.exit(1)
    ifname = (data.get("WIFI_IFNAME") or "").strip() or None
    hidden = (data.get("WIFI_HIDDEN", "").strip().lower() in ("1", "true", "yes", "on"))
    log.info("wifi-apply: конфиг %s", path)
    run_wifi_connect(ssid, pwd, pwfile, ifname, hidden)


def _nm_connection_exists(name: str) -> bool:
    r = subprocess.run(
        ["nmcli", "-t", "-f", "NAME", "connection", "show"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if r.returncode != 0:
        return False
    names = {line.strip() for line in r.stdout.splitlines() if line.strip()}
    return name in names


def _ethernet_uplink_connected(device: str = "eth0") -> bool:
    """Проверяет, есть ли рабочий ethernet uplink для сохранения SSH/интернета."""
    r = subprocess.run(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 3:
            continue
        dev, typ, state = parts
        if dev == device and typ == "ethernet" and state.startswith("connected"):
            return True
    return False


def _log_ap_ssh_hint(ssid: str, ifname: str | None) -> None:
    """После подъёма AP старый SSH по домашнему Wi‑Fi обычно недоступен — подсказка по новому адресу."""
    dev = _wifi_device(ifname)
    gw = "10.42.0.1"
    try:
        r = subprocess.run(
            ["nmcli", "-g", "IP4.ADDRESS", "device", "show", dev],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                addr = line.strip().split("/")[0]
                if addr.startswith("10.42."):
                    gw = addr
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    u = os.environ.get("USER", "pi")
    log.info(
        "AP «%s» на %s: если SSH шёл через домашний Wi‑Fi, сессия оборвётся — один радиоканал перешёл в режим точки. "
        "Подключите ПК к этой AP, затем: ssh %s@%s (часто это 10.42.0.1 у NetworkManager shared).",
        ssid,
        dev,
        u,
        gw,
    )


def _hotspot_up(
    *,
    ssid: str,
    password: str | None,
    ifname: str | None,
    sudo: bool,
) -> tuple[bool, str]:
    dev = _wifi_device(ifname)
    # Надёжный сценарий AP: прямой hotspot-командой, без переиспользования старого профиля.
    # Это избегает ошибок вида "wep-key0 required".
    psk = password
    if not psk:
        psk = "12345678"
    if len(psk) < 8:
        return (
            False,
            f"Пароль точки доступа — {len(psk)} симв., для WPA2 нужно ≥8. "
            "Проверьте --ap-password, RPI_AP_PASSWORD или AP_PASSWORD в config/ap.local.env.",
        )

    cmd = ["nmcli", "device", "wifi", "hotspot", "ssid", ssid, "password", psk]
    if ifname:
        cmd += ["ifname", ifname]
    log.info(
        "nmcli hotspot на %s (sudo=%s), ожидание до ~90 с — пока тихо в логе, это нормально …",
        dev,
        sudo,
    )
    r = _nm_run(cmd, sudo=sudo, timeout=90)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "").strip()

    return True, (r.stdout or "").strip() or f"Hotspot {ssid} поднят на {dev}"


def run_wifi_hotspot(
    ssid: str,
    password: str | None,
    ifname: str | None,
    *,
    require_ethernet_uplink: bool = False,
) -> int:
    """
    Поднимает точку доступа Wi‑Fi через NetworkManager.

    Коды возврата: 0 — ок; 2 — заблокировано (нет eth0 при require_ethernet_uplink); 1 — иная ошибка.
    """
    net = (ssid or "").strip()
    if not net:
        log.error("SSID точки доступа пустой.")
        return 1
    if require_ethernet_uplink and not _ethernet_uplink_connected("eth0"):
        log.error(
            "ETH uplink не активен (eth0 disconnected). Поднятие AP на wlan0 разорвёт текущий Wi‑Fi/SSH. "
            "Подключите ethernet или запустите с принудительным флагом (--ap-force / wifi-hotspot --force)."
        )
        return 2
    if not password:
        log.warning(
            "Пароль AP не задан (ни --ap-password, ни RPI_AP_PASSWORD, ни config/ap.local.env) — "
            "используем запасной WPA2 пароль: 12345678"
        )
    log.info("wifi-hotspot: поднимаем точку доступа «%s» ...", net)

    def _finish_ok(hmsg: str) -> int:
        if hmsg:
            log.info("%s", hmsg)
        _log_ap_ssh_hint(net, ifname)
        return 0

    log.info("wifi-hotspot: nmcli без sudo (если отказ по правам — будет второй вызов с sudo) …")
    ok, msg = _hotspot_up(ssid=net, password=password, ifname=ifname, sudo=False)
    if ok:
        return _finish_ok(msg)

    mlow = msg.lower()
    perm = (
        "not authorized" in mlow
        or "permission" in mlow
        or "insufficient privileges" in mlow
        or "requires privileges" in mlow
        or "access denied" in mlow
    )
    if perm:
        log.info("NetworkManager требует root — повтор с sudo …")
        ok2, msg2 = _hotspot_up(ssid=net, password=password, ifname=ifname, sudo=True)
        if ok2:
            return _finish_ok(msg2)
        log.error("Не удалось поднять hotspot: %s", msg2 or "nmcli error")
        return 1

    log.error("Не удалось поднять hotspot: %s", msg or "nmcli error")
    return 1
