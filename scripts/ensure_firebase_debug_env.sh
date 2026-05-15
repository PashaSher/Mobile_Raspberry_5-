#!/usr/bin/env bash
# Если нет локального firebase.debug.env — копирует пример для Run and Debug.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE="${ROOT}/config/firebase.debug.env.example"
TARGET="${ROOT}/config/firebase.debug.env"
if [[ ! -f "${EXAMPLE}" ]]; then
  echo "[ensure_firebase_debug_env] нет файла: ${EXAMPLE}" >&2
  exit 0
fi
if [[ ! -f "${TARGET}" ]]; then
  cp "${EXAMPLE}" "${TARGET}"
  echo "[ensure_firebase_debug_env] создан ${TARGET} — при необходимости отредактируйте путь к ключу." >&2
fi
exit 0
