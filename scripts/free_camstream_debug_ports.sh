#!/usr/bin/env bash
# Перед отладкой в Cursor: один экземпляр stream_cam — освободить порты 5000 / 5001.
set -u

say() { echo "[free_camstream_debug_ports] $*" >&2; }

# 1) Если поднят systemd-юнит — лучше остановить службу (иначе родитель может сразу поднять новый процесс).
if command -v systemctl >/dev/null 2>&1; then
  for unit in camstream.service camstream; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      if sudo -n systemctl stop "$unit" 2>/dev/null; then
        say "sudo: systemctl stop $unit — ok"
      else
        say "юнит $unit активен, но «sudo -n systemctl stop» не сработал (нужен пароль/NOPASSWD). Остановите: sudo systemctl stop $unit"
      fi
      break
    fi
  done
fi

# 2) Все оставшиеся процессы stream_camera (ручной запуск, старый debug и т.д.).
if pkill -TERM -f 'stream_camera\.py' 2>/dev/null; then
  say "SIGTERM → процессы stream_camera.py"
else
  say "процессов stream_camera.py не найдено (или нет прав)"
fi
sleep 0.4

# 3) На всякий случай снять слушателей с портов (свой пользователь).
for p in 5000 5001; do
  if fuser -k "${p}/tcp" 2>/dev/null; then
    say "fuser -k ${p}/tcp"
  fi
done

# 4) Слушатели от root (без NOPASSWD — тихий пропуск).
if command -v sudo >/dev/null 2>&1; then
  for p in 5000 5001; do
    sudo -n fuser -k "${p}/tcp" 2>/dev/null || true
  done
fi

say "готово"
exit 0
