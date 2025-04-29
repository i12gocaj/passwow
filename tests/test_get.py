from click.testing import CliRunner

from vault.cli import cli


def test_get_existing_entry(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"
    master_pw = "mpass"

    # Crear y poblar vault
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e1", "--user", "u1"],
        input=f"{master_pw}\npass1\npass1\n",
    )

    # Recuperar la entrada
    result = runner.invoke(
        cli, ["get", "--path", str(vault_file), "--name", "e1"], input=f"{master_pw}\n"
    )
    assert result.exit_code == 0
    assert "Nombre:    e1" in result.output
    assert "Usuario:   u1" in result.output
    assert "Password:  pass1" in result.output


def test_get_not_found(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"
    master_pw = "mpass"

    # Solo init, sin añadir la entrada buscada
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )

    result = runner.invoke(
        cli,
        ["get", "--path", str(vault_file), "--name", "nope"],
        input=f"{master_pw}\n",
    )
    assert result.exit_code == 0
    assert "Entrada 'nope' no encontrada." in result.output


def test_get_no_vault(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"

    # Sin init
    result = runner.invoke(
        cli, ["get", "--path", str(vault_file), "--name", "x"], input="any\n"
    )
    assert result.exit_code == 0
    assert f"No se encontró el vault en '{vault_file}'" in result.output
