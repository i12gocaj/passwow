import os
import json
import pytest
from vault.storage import load_entries, save_entries
from vault.crypto import _SALT_SIZE, _IV_SIZE, derive_key, encrypt_data

def test_storage_roundtrip(tmp_path):
    # Preparar vault vacío
    salt = os.urandom(_SALT_SIZE)
    password = "testpass"
    key = derive_key(password, salt)
    initial_data = json.dumps([]).encode()
    iv, ciphertext = encrypt_data(key, initial_data)
    vault_file = tmp_path / "vault.dat"
    vault_file.write_bytes(salt + iv + ciphertext)

    # Leer listas iniciales (vacías)
    entries = load_entries(str(vault_file), password)
    assert entries == []

    # Guardar nueva entrada
    new_entries = [{"name":"test","username":"user","password":"pass","note":"","timestamp":0}]
    save_entries(str(vault_file), password, new_entries)

    # Leer de nuevo y verificar
    loaded = load_entries(str(vault_file), password)
    assert loaded == new_entries