from click.testing import CliRunner

from vault.cli import cli
from vault.storage import load_entries


def test_remove_existing(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"
    master_pw = "mpass"

    # Inicializar y añadir entrada
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "toremove", "--user", "u"],
        input=f"{master_pw}\npass\npass\n",
    )

    # Eliminar la entrada
    result = runner.invoke(
        cli,
        ["remove", "--path", str(vault_file), "--name", "toremove"],
        input=f"{master_pw}\n",
    )
    assert result.exit_code == 0
    assert "Entrada 'toremove' eliminada correctamente." in result.output

    # Verificar con storage
    entries = load_entries(str(vault_file), master_pw)
    assert all(e["name"] != "toremove" for e in entries)


def test_remove_not_found(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"
    master_pw = "mpass"

    # Init sin añadir
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )

    result = runner.invoke(
        cli,
        ["remove", "--path", str(vault_file), "--name", "nope"],
        input=f"{master_pw}\n",
    )
    assert result.exit_code == 0
    assert "Entrada 'nope' no encontrada." in result.output


def test_remove_no_vault(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"

    result = runner.invoke(
        cli, ["remove", "--path", str(vault_file), "--name", "x"], input="any\n"
    )
    assert result.exit_code == 0
    assert f"No se encontró el vault en '{vault_file}'" in result.output
