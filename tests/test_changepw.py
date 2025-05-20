from click.testing import CliRunner
from vault.cli import cli
from vault.storage import load_entries


def test_changepw_success(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_changepw.dat"
    pw1 = "oldpass"
    pw2 = "newpass"
    # Init y añadir entrada
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw1}\n{pw1}\n")
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e1", "--user", "u1"],
        input=f"{pw1}\npass\npass\n",
    )
    # Cambiar contraseña
    result = runner.invoke(
        cli, ["changepw", "--path", str(vault_file)], input=f"{pw1}\n{pw2}\n{pw2}\n"
    )
    assert result.exit_code == 0
    assert "Contraseña maestra cambiada" in result.output
    # Se puede leer con la nueva contraseña
    entries = load_entries(str(vault_file), pw2)
    assert entries[0]["name"] == "e1"
    # Falla con la antigua
    from cryptography.exceptions import InvalidTag
    import pytest

    with pytest.raises(InvalidTag):
        load_entries(str(vault_file), pw1)
