"""
benchmark.py
Script de benchmark para medir rendimiento de cifrado/descifrado del vault.
"""

import os
import json
import time
import argparse

from vault.crypto import derive_key, encrypt_data, _SALT_SIZE
from vault.storage import save_entries, load_entries


def generate_dummy_vault(path: str, master_pw: str, size_bytes: int = 1_000_000):
    """
    Genera un vault cifrado de aproximadamente size_bytes tamaño.
    """
    salt = os.urandom(_SALT_SIZE)
    key = derive_key(master_pw, salt)
    entries = []
    dummy_entry = {
        "name": "entry",
        "username": "user",
        "password": "p" * 50,
        "note": "",
        "timestamp": int(time.time()),
    }
    while True:
        entries.append(dummy_entry)
        data = json.dumps(entries).encode()
        iv, ciphertext = encrypt_data(key, data)
        total = len(salt) + len(iv) + len(ciphertext)
        if total >= size_bytes:
            save_entries(path, master_pw, entries)
            break


def benchmark_unlock(path: str, master_pw: str, iterations: int = 10):
    """
    Mide el tiempo medio de desbloqueo (load_entries) en vault existente.
    """
    times = []
    for _ in range(iterations):
        start = time.time()
        load_entries(path, master_pw)
        times.append(time.time() - start)
    avg = sum(times) / len(times)
    print(f"Unlock average over {iterations} runs: {avg:.4f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark de vault: genera y mide unlock."
    )
    parser.add_argument("--path", default="vault.dat", help="Ruta del vault cifrado")
    parser.add_argument(
        "--pw", default="benchmark", help="Contraseña maestra para el vault"
    )
    parser.add_argument(
        "--size", type=int, default=1000000, help="Tamaño objetivo en bytes"
    )
    parser.add_argument("--iter", type=int, default=10, help="Número de iteraciones")
    args = parser.parse_args()
    generate_dummy_vault(args.path, args.pw, args.size)
    benchmark_unlock(args.path, args.pw, args.iter)
