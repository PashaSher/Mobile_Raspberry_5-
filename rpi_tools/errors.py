"""Исключения уровня camstream/stream_camera."""


class TcpBindError(Exception):
    """Не удалось занять TCP-порт (часто порт уже слушает другой процесс)."""

