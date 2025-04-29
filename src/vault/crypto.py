import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constantes
_SALT_SIZE = 16
_IV_SIZE = 12
_N = 2**14  # Work factor
_R = 8
_P = 1


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes usando Scrypt.
    """
    kdf = Scrypt(salt=salt, length=32, n=_N, r=_R, p=_P)
    return kdf.derive(password.encode())


def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Cifra datos con AES-GCM. Devuelve (iv, ciphertext).
    """
    iv = os.urandom(_IV_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, None)
    return iv, ct


def decrypt_data(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Descifra datos AES-GCM.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
