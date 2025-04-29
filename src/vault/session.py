"""
session.py
Módulo para gestionar sesiones de clave maestra con auto-lock tras timeout.
"""

import json
import base64
import time
from pathlib import Path
from typing import Optional


def load_session(path: str, timeout: int) -> Optional[bytes]:
    """
    Carga la clave derivada almacenada en session file si no ha expirado.
    path: ruta al session JSON.
    timeout: tiempo en segundos antes de expirar.
    Devuelve la clave (bytes) o None si no existe o expiró.
    """
    session_file = Path(path)
    if not session_file.exists():
        return None
    try:
        data = json.loads(session_file.read_text())
        ts = data.get("timestamp", 0)
        if time.time() - ts <= timeout:
            return base64.b64decode(data.get("key", ""))
        else:
            clear_session(path)
            return None
    except (ValueError, KeyError):
        # JSON inválido
        clear_session(path)
        return None


def save_session(path: str, key: bytes) -> None:
    """
    Guarda la clave derivada en un session file con timestamp actual.
    """
    session_file = Path(path)
    session_file.parent.mkdir(parents=True, exist_ok=True)
    data = {"key": base64.b64encode(key).decode(), "timestamp": int(time.time())}
    session_file.write_text(json.dumps(data))


def clear_session(path: str) -> None:
    """
    Elimina el session file, forzando auto-lock.
    """
    session_file = Path(path)
    if session_file.exists():
        session_file.unlink()
