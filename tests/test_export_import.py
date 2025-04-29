from click.testing import CliRunner

from vault.cli import cli
from vault.storage import load_entries


def test_export_success(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    master_pw = "mpass"

    # 1) Inicializar y poblar vault
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e1", "--user", "u1"],
        input=f"{master_pw}\npass1\npass1\n",
    )

    # 2) Exportar a otro fichero
    dest = tmp_path / "copia.dat"
    result = runner.invoke(
        cli,
        ["export", "--path", str(vault_file), "--file", str(dest)],
        input=f"{master_pw}\n",
    )
    assert result.exit_code == 0
    assert f"Vault exportado a '{dest}' correctamente." in result.output
    # El fichero existe y su contenido es idéntico
    assert dest.exists()
    assert dest.read_bytes() == vault_file.read_bytes()
    # Podemos leerlo con load_entries
    entries = load_entries(str(dest), master_pw)
    assert len(entries) == 1
    assert entries[0]["name"] == "e1"


def test_export_no_vault(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    dest = tmp_path / "copia.dat"
    # Sin init
    result = runner.invoke(
        cli, ["export", "--path", str(vault_file), "--file", str(dest)], input="any\n"
    )
    assert result.exit_code == 0
    assert f"No se encontró el vault en '{vault_file}'" in result.output


def test_export_bad_password(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault.dat"
    master_pw = "mpass"
    # Init
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    # Intentar exportar con contraseña incorrecta
    result = runner.invoke(
        cli,
        ["export", "--path", str(vault_file), "--file", str(tmp_path / "copia.dat")],
        input="wrongpass\n",
    )
    assert result.exit_code == 0
    assert "Contraseña maestra incorrecta." in result.output


def test_import_success(tmp_path):
    runner = CliRunner()
    vault_src = tmp_path / "orig.dat"
    vault_dest = tmp_path / "imported.dat"
    master_pw = "mpass"

    # Crear un vault de origen
    runner.invoke(
        cli, ["init", "--path", str(vault_src)], input=f"{master_pw}\n{master_pw}\n"
    )
    runner.invoke(
        cli,
        ["add", "--path", str(vault_src), "--name", "e2", "--user", "u2"],
        input=f"{master_pw}\npass2\npass2\n",
    )

    # Importar a vault_dest
    result = runner.invoke(
        cli, ["import", "--path", str(vault_dest), "--file", str(vault_src)]
    )
    assert result.exit_code == 0
    assert (
        f"Vault importado desde '{vault_src}' a '{vault_dest}' correctamente."
        in result.output
    )
    # Comprobar que podemos leerlo
    entries = load_entries(str(vault_dest), master_pw)
    assert len(entries) == 1
    assert entries[0]["name"] == "e2"


def test_import_no_source(tmp_path):
    runner = CliRunner()
    vault_dest = tmp_path / "imported.dat"
    src = tmp_path / "noexist.dat"
    # Sin fichero origen
    result = runner.invoke(
        cli, ["import", "--path", str(vault_dest), "--file", str(src)]
    )
    assert result.exit_code == 0
    assert f"No se encontró el fichero de importación en '{src}'." in result.output
