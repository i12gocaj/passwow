import os
from click.testing import CliRunner
import pytest

from vault.cli import cli
from vault.storage import load_entries


def test_add_creates_entry(tmp_path):
    # Preparar ruta de vault y runner
    vault_file = tmp_path / "vault_test.dat"
    runner = CliRunner()

    # 1) Inicializar vault
    master_pw = "masterpass"
    result_init = runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    assert result_init.exit_code == 0

    # 2) Añadir entrada
    name = "testentry"
    username = "user1"
    entry_pw = "secret123"
    # Inputs: contraseña maestra, luego contraseña de entrada dos veces
    inputs = f"{master_pw}\n{entry_pw}\n{entry_pw}\n"
    result_add = runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", name, "--user", username],
        input=inputs,
    )
    assert result_add.exit_code == 0
    assert f"Entrada '{name}' añadida correctamente." in result_add.output

    # 3) Verificar con la capa de almacenamiento
    entries = load_entries(str(vault_file), master_pw)
    assert isinstance(entries, list)
    found = [e for e in entries if e["name"] == name]
    assert len(found) == 1
    entry = found[0]
    assert entry["username"] == username
    assert entry["password"] == entry_pw
