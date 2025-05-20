from click.testing import CliRunner

from vault.cli import cli


def test_list_empty(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    master_pw = "mpass"

    # Inicializar vault vacío
    result_init = runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    assert result_init.exit_code == 0

    # Listar entradas (debe estar vacío)
    result = runner.invoke(
        cli, ["list", "--path", str(vault_file)], input=f"{master_pw}\n"
    )
    assert result.exit_code == 0
    assert "No hay entradas" in result.output


def test_list_multiple(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    master_pw = "mpass"

    # Inicializar y añadir dos entradas
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e1", "--user", "u1"],
        input=f"{master_pw}\npass1\npass1\n",
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e2", "--user", "u2"],
        input=f"{master_pw}\npass2\npass2\n",
    )

    # Listar entradas (debe listar e1 y e2)
    result = runner.invoke(
        cli, ["list", "--path", str(vault_file)], input=f"{master_pw}\n"
    )
    assert result.exit_code == 0
    # Encabezado
    assert "Nombre" in result.output and "Creado" in result.output
    # Entradas
    assert "e1" in result.output
    assert "e2" in result.output
