from click.testing import CliRunner

from vault.cli import cli
from vault.session import DEFAULT_SESSION_DIR  # Sigue siendo útil para .name
import vault.session  # Necesario para monkeypatch


def test_bruteforce_wipe(tmp_path, monkeypatch):  # Añadido monkeypatch
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"

    # Directorio esperado para los archivos de sesión/fallos dentro de tmp_path para este test
    expected_session_dir_in_tmp = (
        tmp_path / DEFAULT_SESSION_DIR.name
    )  # Esto es tmp_path / ".passwow"

    # Ruta donde el test espera que se cree/encuentre el archivo .fail
    fail_file = expected_session_dir_in_tmp / (vault_file.name + ".fail")

    master_pw = "correctpass"

    # Aplicar monkeypatch a la constante en el módulo vault.session
    # para que el código de la CLI use esta ruta basada en tmp_path.
    monkeypatch.setattr(
        vault.session, "DEFAULT_SESSION_DIR", expected_session_dir_in_tmp
    )

    # 1) Inicializar vault
    result_init = runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    if result_init.exit_code != 0:
        print("\n[DEBUG OUTPUT INIT]\n" + result_init.output)
    assert result_init.exit_code == 0
    assert vault_file.exists()
    # El fail_file no debería existir después de un init exitoso
    assert not fail_file.exists()

    # 2) Intentar desbloquear con contraseña incorrecta 5 veces
    wrong_pw = "wrongpass"
    for attempt in range(1, 6):
        result = runner.invoke(
            cli,
            ["get", "--path", str(vault_file), "--name", "any"],
            input=f"{wrong_pw}\\n"
            # Eliminado env={"HOME": str(tmp_path)}
        )
        assert result.exit_code == 0
        if attempt < 5:
            # Debe informar intentos restantes
            remaining = 5 - attempt
            assert (
                f"Contraseña maestra incorrecta. Te quedan {remaining} intento"
                in result.output
            )
            # El vault sigue existiendo y el fichero .fail refleja el conteo
            assert vault_file.exists()
            assert fail_file.exists()  # Ahora debería encontrarlo en la nueva ruta
            assert fail_file.read_text() == str(attempt)
        else:
            # En el 5º intento, auto-wipe
            out = result.output.lower()
            assert (
                "demasiados intentos fallidos" in out
                and "vault ha sido eliminado por seguridad" in out
            )
            assert not vault_file.exists()
            assert not fail_file.exists()  # También se elimina el fail_file

    # 3) Tras el wipe, un nuevo intento indica vault no encontrado
    result_after = runner.invoke(
        cli,
        ["get", "--path", str(vault_file), "--name", "any"],
        input=f"{master_pw}\\n"
        # Eliminado env={"HOME": str(tmp_path)}
    )
    assert result_after.exit_code == 0
    assert f"No se encontró el vault en '{vault_file}'" in result_after.output
