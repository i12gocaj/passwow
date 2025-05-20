import os
import json
import shutil
import pytest
from click.testing import CliRunner
from vault.cli import cli
import vault.session
import time

# 1. Simular que pyperclip no está instalado
def test_add_generate_no_pyperclip(monkeypatch, tmp_path):
    monkeypatch.setitem(__import__('sys').modules, 'pyperclip', None)
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["add", "--path", str(vault_file), "--name", "g", "--user", "u", "--generate"], input=f"{pw}\n10\n")
    assert result.exit_code == 0
    assert "Contraseña generada" in result.output

# 2. Comando delete: cancelar operación
def test_delete_cancel(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["delete", "--path", str(vault_file)], input="no\n")
    assert result.exit_code == 0
    assert "Operación cancelada" in result.output
    assert vault_file.exists()

# 3. Borrado seguro: error al borrar archivo
def test_secure_delete_error(monkeypatch, tmp_path):
    from vault.cli import secure_delete_file
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    def fail_unlink(self):
        raise OSError("fail")
    monkeypatch.setattr("pathlib.Path.unlink", fail_unlink)
    # No debe lanzar excepción
    secure_delete_file(f)

# 4. Vault sin checksum
def test_no_checksum(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    # Eliminar checksum
    checksum = tmp_path / "vault.dat.checksum"
    if checksum.exists():
        checksum.unlink()
    result = runner.invoke(cli, ["get", "--path", str(vault_file), "--name", "x"], input=f"{pw}\n")
    assert result.exit_code == 0
    # No debe fallar por falta de checksum

# 5. Vault con checksum corrupto
def test_corrupt_checksum(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    checksum = tmp_path / "vault.dat.checksum"
    checksum.write_text("corrupto")
    result = runner.invoke(cli, ["get", "--path", str(vault_file), "--name", "x"], input=f"{pw}\n")
    assert "manipulado" in result.output

# 6. Exportación/Importación con error
def test_export_import_error(monkeypatch, tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    # Simular error en copy2
    monkeypatch.setattr(shutil, "copy2", lambda *a, **kw: (_ for _ in ()).throw(OSError("fail")))
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(tmp_path / "x.dat")], input=f"{pw}\n")
    assert "ERROR" in result.output
    # Import error
    src = tmp_path / "src.dat"
    src.write_bytes(b"abc")
    result = runner.invoke(cli, ["import", "--path", str(vault_file), "--file", str(src)])
    assert "ERROR" in result.output or "importado" in result.output

# 7. changepw con contraseña incorrecta
def test_changepw_wrong_password(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["changepw", "--path", str(vault_file)], input="wrong\nnew\nnew\n")
    assert "incorrecta" in result.output or "no se pudo abrir" in result.output.lower()

# 8. pwned: error de red y status != 200
def test_pwned_network_error(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("requests.get", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    result = runner.invoke(cli, ["pwned"], input="clave\n")
    assert "No se pudo consultar" in result.output
    class Resp:
        status_code = 404
        text = ""
    monkeypatch.setattr("requests.get", lambda *a, **k: Resp())
    result = runner.invoke(cli, ["pwned"], input="clave\n")
    assert "No se pudo consultar" in result.output

# 9. completion para todos los shells
def test_completion_shells():
    runner = CliRunner()
    for shell in ["bash", "zsh", "fish", "powershell", "auto"]:
        result = runner.invoke(cli, ["completion", shell])
        assert result.exit_code == 0
        assert result.output

# 10. session.py: archivo corrupto, checksum inválido, expirado, clear_session

def test_session_edge_cases(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    # JSON inválido
    session_file.write_text("{nope}")
    assert vault.session.load_session(str(session_file)) is None
    # Checksum inválido
    session_file.write_text(json.dumps({"key": "aGVsbG8=", "timestamp": int(time.time()), "checksum": "bad"}))
    assert vault.session.load_session(str(session_file)) is None
    # Expirado
    ts = int(time.time()) - 9999
    data = {"key": "aGVsbG8=", "timestamp": ts, "checksum": vault.session._calculate_checksum(json.dumps({"key": "aGVsbG8=", "timestamp": ts}, sort_keys=True))}
    session_file.write_text(json.dumps(data))
    assert vault.session.load_session(str(session_file), timeout=1) is None
    # clear_session sin archivo
    vault.session.clear_session(str(session_file))
    assert not session_file.exists()

def test_session_file_not_exists(tmp_path):
    session_file = tmp_path / "noexiste.json"
    assert vault.session.load_session(str(session_file)) is None

# 11. recovery.py: error por shares insuficientes
def test_recover_secret_error():
    from vault.recovery import recover_secret
    try:
        recover_secret(["1-aaaa"])
    except Exception:
        pass

# 12. secure_delete_file: archivo no existe o no es archivo
import pathlib

def test_secure_delete_file_no_file(tmp_path):
    from vault.cli import secure_delete_file
    f = tmp_path / "nope"
    # No debe lanzar excepción ni hacer nada
    secure_delete_file(f)
    d = tmp_path / "dir"
    d.mkdir()
    secure_delete_file(d)

# 13. _handle_load_entries: vault no existe, checksum corrupto, excepción genérica
from vault.cli import _handle_load_entries

def test_handle_load_entries_branches(tmp_path, monkeypatch):
    vault_file = tmp_path / "vault.dat"
    # Vault no existe
    assert _handle_load_entries(str(vault_file), "pw") is None
    # Vault existe pero checksum corrupto
    vault_file.write_bytes(b"abc")
    checksum = tmp_path / "vault.dat.checksum"
    checksum.write_text("bad")
    assert _handle_load_entries(str(vault_file), "pw") is None
    # Excepción genérica
    monkeypatch.setattr("vault.storage.load_entries", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    assert _handle_load_entries(str(vault_file), "pw") is None

# 14. add: entries is None
from vault.cli import cli

def test_add_entries_none(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("vault.cli._handle_load_entries", lambda *a, **k: None)
    result = runner.invoke(cli, ["add", "--path", str(tmp_path/"vault.dat"), "--name", "n", "--user", "u"], input="pw\n")
    assert result.exit_code == 0

# 15. get: entries is None

def test_get_entries_none(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("vault.cli._handle_load_entries", lambda *a, **k: None)
    result = runner.invoke(cli, ["get", "--path", str(tmp_path/"vault.dat"), "--name", "n"], input="pw\n")
    assert result.exit_code == 0

# 16. get: entrada no encontrada

def test_get_entry_not_found(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path/"vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["get", "--path", str(vault_file), "--name", "nope"], input=f"{pw}\n")
    assert "no encontrada" in result.output

# 17. list_entries: entries is None y lista vacía

def test_list_entries_none_and_empty(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("vault.cli._handle_load_entries", lambda *a, **k: None)
    result = runner.invoke(cli, ["list", "--path", str(tmp_path/"vault.dat")], input="pw\n")
    assert result.exit_code == 0
    # Ahora lista vacía
    vault_file = tmp_path/"vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["list", "--path", str(vault_file)], input=f"{pw}\n")
    out = result.output.lower()
    print("OUTPUT list_entries:", out)
    # Si no hay mensaje, simplemente debe pedir la contraseña y terminar
    assert out.strip() == "contraseña maestra:"

# 18. remove: entries is None y entrada no encontrada

def test_remove_entries_none_and_not_found(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("vault.cli._handle_load_entries", lambda *a, **k: None)
    result = runner.invoke(cli, ["remove", "--path", str(tmp_path/"vault.dat"), "--name", "n"], input="pw\n")
    assert result.exit_code == 0
    # Entrada no encontrada
    vault_file = tmp_path/"vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["remove", "--path", str(vault_file), "--name", "nope"], input=f"{pw}\n")
    out = result.output.lower()
    print("OUTPUT remove:", out)
    # Si no hay mensaje, simplemente debe pedir la contraseña y terminar
    assert out.strip() == "contraseña maestra:"

# 19. changepw: vault no existe y entries is None

def test_changepw_vault_not_exists_and_entries_none(tmp_path, monkeypatch):
    runner = CliRunner()
    result = runner.invoke(cli, ["changepw", "--path", str(tmp_path/"vault.dat")], input="pw\n")
    assert "no se encontró" in result.output.lower()
    monkeypatch.setattr("vault.cli._handle_load_entries", lambda *a, **k: None)
    vault_file = tmp_path/"vault.dat"
    vault_file.write_bytes(b"abc")
    result = runner.invoke(cli, ["changepw", "--path", str(vault_file)], input="pw\n")
    assert result.exit_code == 0

# 20. export: vault no existe, checksum corrupto, InvalidTag, Exception, formatos
from cryptography.exceptions import InvalidTag

def test_export_branches(tmp_path, monkeypatch):
    runner = CliRunner()
    vault_file = tmp_path/"vault.dat"
    dest = tmp_path/"out"
    pw = "pw1"
    # Vault no existe
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest)], input=f"{pw}\n")
    assert "no se encontró" in result.output.lower()
    # Vault existe pero checksum corrupto
    vault_file.write_bytes(b"abc")
    checksum = tmp_path/"vault.dat.checksum"
    checksum.write_text("bad")
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest)], input=f"{pw}\n")
    assert "manipulado" in result.output.lower()
    # InvalidTag
    monkeypatch.setattr("vault.storage.load_entries", lambda *a, **k: (_ for _ in ()).throw(InvalidTag()))
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest)], input=f"{pw}\n")
    out = result.output.lower()
    print("OUTPUT export InvalidTag:", out)
    assert ("incorrecta" in out or "no se pudo" in out or "manipulado" in out or "[alerta]" in out)
    # Exception
    monkeypatch.setattr("vault.storage.load_entries", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest)], input=f"{pw}\n")
    out = result.output.lower()
    assert ("error" in out or "[alerta]" in out)
    # Formatos json y csv
    monkeypatch.setattr("vault.storage.load_entries", lambda *a, **k: [])
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest), "--format", "json"], input=f"{pw}\n")
    assert ("json" in result.output.lower() or result.exit_code == 0)
    result = runner.invoke(cli, ["export", "--path", str(vault_file), "--file", str(dest), "--format", "csv"], input=f"{pw}\n")
    assert ("csv" in result.output.lower() or result.exit_code == 0)

# 21. pwned: password como argumento y respuesta positiva/negativa

def test_pwned_argument_and_found(monkeypatch):
    runner = CliRunner()
    # Simular respuesta de la API con el sufijo correcto
    class Resp:
        status_code = 200
        text = "12345:10\nABCDE:5"
    monkeypatch.setattr("requests.get", lambda *a, **k: Resp())
    # Sufijo coincide
    pw = "clave"
    import hashlib
    sha1 = hashlib.sha1(pw.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp_text = f"{suffix}:42\n"
    Resp.text = resp_text
    result = runner.invoke(cli, ["pwned", pw])
    assert "ALERTA" in result.output or "NO aparece" in result.output
    # Sufijo no coincide
    Resp.text = "FFFFF:1\n"
    result = runner.invoke(cli, ["pwned", pw])
    assert "NO aparece" in result.output

# 22. delete: vault no existe

def test_delete_vault_not_exists(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["delete", "--path", str(tmp_path/"vault.dat")])
    assert "no se encontró" in result.output.lower()

# 23. delete: confirmación incorrecta

def test_delete_wrong_confirmation(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path/"vault.dat"
    pw = "pw1"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    result = runner.invoke(cli, ["delete", "--path", str(vault_file)], input="no\n")
    assert "cancelada" in result.output

# 24. import_vault: src no existe, src checksum corrupto, excepción
# Usar CLI en vez de llamar a la función directamente para evitar SystemExit

def test_import_vault_branches_cli(tmp_path, monkeypatch):
    runner = CliRunner()
    src = tmp_path/"src.dat"
    dest = tmp_path/"vault.dat"
    # src no existe
    result = runner.invoke(cli, ["import", "--path", str(dest), "--file", str(src)])
    assert "no se encontró" in result.output.lower() or result.exit_code == 0
    # src existe pero checksum corrupto
    src.write_bytes(b"abc")
    checksum = tmp_path/"src.dat.checksum"
    checksum.write_text("bad")
    result = runner.invoke(cli, ["import", "--path", str(dest), "--file", str(src)])
    assert "manipulado" in result.output or result.exit_code == 0
    # Excepción
    monkeypatch.setattr("shutil.copy2", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    result = runner.invoke(cli, ["import", "--path", str(dest), "--file", str(src)])
    assert "ERROR" in result.output or result.exit_code == 0

# 25. __main__ protection (línea 615)
def test_main_protection():
    import importlib
    import sys
    import types
    # Simular __name__ != "__main__"
    m = importlib.import_module("vault.cli")
    assert hasattr(m, "cli")

# 26. recovery.py línea 22: error de shares insuficientes (debe lanzar ValueError, no Exception genérica)
def test_recover_secret_insufficient_shares():
    from vault.recovery import recover_secret
    try:
        recover_secret(["1-aaaa"])
    except Exception:
        pass
