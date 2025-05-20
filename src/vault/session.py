"""
session.py
Módulo para gestionar sesiones de clave maestra con auto-lock tras timeout.
"""

import json
import base64
import time
from pathlib import Path
from typing import Optional
import hashlib  # Añadido para checksum

# Nombre del archivo de sesión por defecto, relativo a la home del usuario
DEFAULT_SESSION_DIR = Path.home() / ".passwow"
DEFAULT_SESSION_FILE = DEFAULT_SESSION_DIR / "session.json"


def _calculate_checksum(data: str) -> str:
    """Calcula un checksum SHA-256 para una cadena de datos."""
    return hashlib.sha256(data.encode()).hexdigest()


def load_session(
    path: str = str(DEFAULT_SESSION_FILE), timeout: int = 300
) -> Optional[bytes]:
    """
    Carga la clave derivada almacenada en session file si no ha expirado y el checksum es válido.
    path: ruta al session JSON.
    timeout: tiempo en segundos antes de expirar.
    Devuelve la clave (bytes) o None si no existe, expiró o fue manipulado.
    """
    session_file = Path(path)
    if not session_file.exists():
        return None
    try:
        content = session_file.read_text()
        data = json.loads(content)

        stored_checksum = data.get("checksum")
        key_b64 = data.get("key", "")
        ts = data.get("timestamp", 0)

        # Recrear los datos para el checksum sin el propio checksum
        data_for_checksum = json.dumps(
            {"key": key_b64, "timestamp": ts}, sort_keys=True
        )

        if (
            not stored_checksum
            or _calculate_checksum(data_for_checksum) != stored_checksum
        ):
            # Checksum inválido o ausente, posible manipulación
            clear_session(path)
            return None

        if time.time() - ts <= timeout:
            return base64.b64decode(key_b64)
        else:
            clear_session(path)
            return None
    except (ValueError, KeyError, json.JSONDecodeError):
        # JSON inválido o claves faltantes
        clear_session(path)
        return None


def save_session(path: str = str(DEFAULT_SESSION_FILE), key: bytes = b"") -> None:
    """
    Guarda la clave derivada en un session file con timestamp actual y checksum.
    """
    session_file = Path(path)
    session_file.parent.mkdir(parents=True, exist_ok=True)

    key_b64 = base64.b64encode(key).decode()
    ts = int(time.time())

    data_to_checksum = json.dumps({"key": key_b64, "timestamp": ts}, sort_keys=True)
    checksum = _calculate_checksum(data_to_checksum)

    data_to_save = {"key": key_b64, "timestamp": ts, "checksum": checksum}

    session_file.write_text(json.dumps(data_to_save))
    # Asegurar permisos restrictivos para el archivo de sesión
    session_file.chmod(0o600)


def clear_session(path: str = str(DEFAULT_SESSION_FILE)) -> None:
    """
    Elimina el session file, forzando auto-lock.
    """
    session_file = Path(path)
    if session_file.exists():
        session_file.unlink()
