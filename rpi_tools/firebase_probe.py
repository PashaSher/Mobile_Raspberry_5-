"""Диагностика Firebase Realtime Database: подбор databaseURL и проверка записи в /rooms/{id}."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def _project_id_from_cred(cred_path: str) -> str:
    meta = json.loads(Path(cred_path).expanduser().read_text(encoding="utf-8"))
    pid = meta.get("project_id")
    if not pid:
        raise ValueError("В JSON сервисного аккаунта нет поля project_id")
    return str(pid)


def _candidate_urls(project_id: str) -> list[str]:
    pid = project_id.strip()
    return [
        f"https://{pid}-default-rtdb.firebaseio.com",
        f"https://{pid}-default-rtdb.europe-west1.firebasedatabase.app",
        f"https://{pid}-default-rtdb.us-central1.firebasedatabase.app",
        f"https://{pid}-default-rtdb.asia-southeast1.firebasedatabase.app",
        f"https://{pid}.firebaseio.com",
    ]


def run_firebase_rtdb_probe(
    cred_path: str,
    room_id: str,
    *,
    database_url_override: str | None = None,
) -> int:
    """
    Пробует databaseURL и имитирует create_room как в FirebaseSignaling.
    Код 0 при успехе, 1 если ни один URL не подошёл.
    """
    try:
        import firebase_admin
        from firebase_admin import credentials, db as rtdb
    except ImportError:
        print(
            "Нет пакета firebase_admin: pip install firebase-admin (в venv на Pi)",
            file=sys.stderr,
        )
        return 1

    cred_path_exp = str(Path(cred_path).expanduser())
    if not Path(cred_path_exp).is_file():
        print(f"Файл ключа не найден: {cred_path_exp}", file=sys.stderr)
        return 1

    cred = credentials.Certificate(cred_path_exp)
    project_id = _project_id_from_cred(cred_path_exp)
    urls: list[str] = (
        [database_url_override.strip()] if database_url_override else _candidate_urls(project_id)
    )

    print(f"project_id из ключа: {project_id}")
    print(f"Проверка записи и узла rooms/{room_id}…")

    last_err: str | None = None
    for url in urls:
        try:
            try:
                firebase_admin.delete_app(firebase_admin.get_app())
            except ValueError:
                pass
            firebase_admin.initialize_app(cred, {"databaseURL": url})
            probe_ref = rtdb.reference("/_camstream_firebase_probe")
            probe_ref.set({"t": time.time()})
            probe_ref.delete()

            base = rtdb.reference(f"/rooms/{room_id}")
            try:
                base.delete()
            except Exception:
                pass
            base.child("status").set("waiting")
            snap = base.get()

            print()
            print("УСПЕХ. Укажите в webrtc именно:")
            print(f"  --firebase-db-url {url}")
            print()
            print("Консоль: Firebase → Build → Realtime Database → Data (не Firestore!)")
            print(f"Путь: rooms → {room_id} → статус записан:", snap)
            try:
                firebase_admin.delete_app(firebase_admin.get_app())
            except Exception:
                pass
            return 0
        except Exception as e:
            last_err = f"{url}: {type(e).__name__}: {e}"
            print(f"  × {last_err}")

    print("\nНи один databaseURL не дал записать данные.", file=sys.stderr)
    print("Убедитесь, что в проекте создана Realtime Database.", file=sys.stderr)
    if last_err:
        print(f"Последняя ошибка: {last_err}", file=sys.stderr)
    return 1
