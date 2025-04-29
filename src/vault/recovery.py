"""
recovery.py
Módulo de recuperación de la clave maestra usando Shamir's Secret Sharing.
"""

# Workaround for Python 3 compatibility with secretsharing library
import builtins

builtins.long = int

# Monkey-patch secretsharing.entropy to support bytes.encode('hex') in Python 3
import binascii
import secretsharing.entropy as _entropy

from secretsharing import PlaintextToHexSecretSharer


class _BytesWithEncode(bytes):
    def encode(self, encoding):
        if encoding == "hex":
            return binascii.hexlify(self).decode()
        return super().encode(encoding)


_entropy.get_entropy_orig = _entropy.get_entropy
_entropy.get_entropy = lambda n: _BytesWithEncode(_entropy.get_entropy_orig(n))


def split_secret(secret: str, n: int, k: int) -> list[str]:
    """
    Divide la contraseña maestra en n partes, recuperables con k de ellas.
    """
    shares = PlaintextToHexSecretSharer.split_secret(secret, k, n)
    return shares


def recover_secret(shares: list[str]) -> str:
    """
    Recobra la contraseña maestra a partir de al menos k shares.
    """
    return PlaintextToHexSecretSharer.recover_secret(shares)
