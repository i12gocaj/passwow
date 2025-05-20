from click.testing import CliRunner
from vault.cli import cli


def test_delete_secure(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_del.dat"
    pw = "delpass"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    # Ejecutar delete (contraseña y confirmación)
    result = runner.invoke(
        cli, ["delete", "--path", str(vault_file)], input=f"{pw}\nBORRAR\n"
    )
    assert result.exit_code == 0
    assert "eliminados de forma segura" in result.output
    # El archivo ya no existe
    assert not vault_file.exists()
