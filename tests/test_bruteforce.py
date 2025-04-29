from click.testing import CliRunner

from vault.cli import cli


def test_bruteforce_wipe(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    fail_file = tmp_path / "vault.dat.fail"
    master_pw = "correctpass"

    # 1) Inicializar vault
    result_init = runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    assert result_init.exit_code == 0
    assert vault_file.exists()
    assert not fail_file.exists()

    # 2) Intentar desbloquear con contraseña incorrecta 5 veces
    wrong_pw = "wrongpass"
    for attempt in range(1, 6):
        result = runner.invoke(
            cli,
            ["get", "--path", str(vault_file), "--name", "any"],
            input=f"{wrong_pw}\n",
        )
        assert result.exit_code == 0
        if attempt < 5:
            # Debe informar intentos restantes
            remaining = 5 - attempt
            assert (
                f"Contraseña maestra incorrecta. Te quedan {remaining} intentos."
                in result.output
            )
            # El vault sigue existiendo y el fichero .fail refleja el conteo
            assert vault_file.exists()
            assert fail_file.exists()
            assert fail_file.read_text() == str(attempt)
        else:
            # En el 5º intento, auto-wipe
            assert (
                "Demasiados intentos fallidos; el vault ha sido eliminado por seguridad."
                in result.output
            )
            assert not vault_file.exists()
            assert not fail_file.exists()

    # 3) Tras el wipe, un nuevo intento indica vault no encontrado
    result_after = runner.invoke(
        cli, ["get", "--path", str(vault_file), "--name", "any"], input=f"{master_pw}\n"
    )
    assert result_after.exit_code == 0
    assert f"No se encontró el vault en '{vault_file}'" in result_after.output
