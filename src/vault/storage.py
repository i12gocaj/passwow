import os
import json
from vault.crypto import derive_key, decrypt_data, encrypt_data, _SALT_SIZE, _IV_SIZE


def load_entries(path: str, password: str) -> list[dict]:
    """
    Lee el fichero cifrado en 'path', lo descifra usando 'password'
    y devuelve la lista de entradas (JSON) contenida.
    """
    # Leer datos crudos
    with open(path, "rb") as f:
        data = f.read()
    # Separar salt, iv y ciphertext
    salt = data[:_SALT_SIZE]
    iv = data[_SALT_SIZE : _SALT_SIZE + _IV_SIZE]
    ciphertext = data[_SALT_SIZE + _IV_SIZE :]
    # Derivar clave y descifrar
    key = derive_key(password, salt)
    plaintext = decrypt_data(key, iv, ciphertext)
    # Parsear JSON
    return json.loads(plaintext.decode())


def save_entries(path: str, password: str, entries: list[dict]) -> None:
    """
    Cifra y escribe la lista de entradas en 'path', usando la sal ya existente
    en el fichero para derivar la clave.
    """
    # Leer salt existente
    with open(path, "rb") as f:
        raw = f.read()
    salt = raw[:_SALT_SIZE]
    # Derivar clave con la misma sal
    key = derive_key(password, salt)
    # Serializar y cifrar
    plaintext = json.dumps(entries).encode()
    iv, ciphertext = encrypt_data(key, plaintext)
    # Sobrescribir fichero: salt + iv + ciphertext
    with open(path, "wb") as f:
        f.write(salt + iv + ciphertext)
