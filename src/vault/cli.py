import click
import os
import json
import time
import datetime

import shutil

from vault.crypto import derive_key, encrypt_data, _SALT_SIZE
from vault.storage import load_entries, save_entries

from pathlib import Path
from cryptography.exceptions import InvalidTag

from vault.session import load_session, save_session, clear_session

from vault.recovery import split_secret, recover_secret

# Session file and timeout (seconds)
SESSION_PATH = os.path.expanduser("~/.passwow/session.json")
LOCK_TIMEOUT = 300  # 5 minutes

_MAX_ATTEMPTS = 5


def _fail_file(path: str) -> Path:
    """Return the path for the failure count file."""
    return Path(path).with_suffix(Path(path).suffix + ".fail")


def record_fail(path: str) -> int:
    """Increment and return the number of failed attempts for this vault."""
    fpath = _fail_file(path)
    count = int(fpath.read_text() or "0") if fpath.exists() else 0
    count += 1
    fpath.write_text(str(count))
    return count


def clear_fail(path: str):
    """Clear the failure count for this vault."""
    fpath = _fail_file(path)
    if fpath.exists():
        fpath.unlink()


def get_master_password():
    """
    Devuelve la contraseña maestra de la sesión si aún es válida,
    o solicita una nueva y la guarda.
    """
    pw_bytes = load_session(SESSION_PATH, LOCK_TIMEOUT)
    if pw_bytes:
        return pw_bytes.decode()
    # Solicitar nueva contraseña maestra
    pw = click.prompt("Contraseña maestra", hide_input=True, confirmation_prompt=False)
    # Guardar en sesión
    save_session(SESSION_PATH, pw.encode())
    return pw


@click.group()
def cli():
    """Gestor de contraseñas local."""
    pass


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
@click.option(
    "--password",
    prompt="Contraseña maestra",
    hide_input=True,
    confirmation_prompt=True,
    help="Contraseña maestra para inicializar el vault",
)
def init(path, password):
    """
    Inicializa un nuevo vault.
    """
    # Generar salt aleatorio y derivar la clave
    salt = os.urandom(_SALT_SIZE)
    key = derive_key(password, salt)

    # Datos iniciales vacíos (lista JSON)
    initial_data = json.dumps([]).encode()

    # Cifrar datos iniciales
    iv, ciphertext = encrypt_data(key, initial_data)

    # Escribir salt + iv + ciphertext en disco
    with open(path, "wb") as vault_file:
        vault_file.write(salt + iv + ciphertext)

    clear_fail(path)
    clear_session(SESSION_PATH)

    click.echo(f"Vault inicializado en {path}.")


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
@click.option("--name", required=True, help="Identificador único de la entrada")
@click.option("--user", "username", required=True, help="Nombre de usuario/login")
@click.option("--note", default="", help="Nota opcional para la entrada")
def add(path, name, username, note):
    """
    Añade una nueva entrada al vault.
    """
    password = get_master_password()
    # 1) Cargar las entradas existentes
    try:
        entries = load_entries(path, password)
        clear_fail(path)
    except FileNotFoundError:
        click.echo(
            f"No se encontró el vault en '{path}'. Por favor, ejecuta 'vault init' primero."
        )
        return
    except InvalidTag:
        # Bad master password
        count = record_fail(path)
        if count >= _MAX_ATTEMPTS:
            # Wipe vault and reset failure count
            Path(path).unlink(missing_ok=True)
            clear_fail(path)
            click.echo(
                "Demasiados intentos fallidos; el vault ha sido eliminado por seguridad."
            )
        else:
            left = _MAX_ATTEMPTS - count
            click.echo(f"Contraseña maestra incorrecta. Te quedan {left} intentos.")
        return

    entry_pass = click.prompt(
        "Contraseña para la entrada",
        hide_input=True,
        confirmation_prompt=True,
    )

    # 2) Construir la nueva entrada
    new_entry = {
        "name": name,
        "username": username,
        "password": entry_pass,
        "note": note,
        "timestamp": int(time.time()),
    }

    # 3) Añadir y guardar
    entries.append(new_entry)
    save_entries(path, password, entries)

    click.echo(f"Entrada '{name}' añadida correctamente.")


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
@click.option(
    "--name",
    "entry_name",
    required=True,
    help="Identificador único de la entrada a recuperar",
)
def get(path, entry_name):
    """
    Recupera y muestra los detalles de una entrada.
    """
    password = get_master_password()
    # Cargar entradas
    try:
        entries = load_entries(path, password)
        clear_fail(path)
    except FileNotFoundError:
        click.echo(
            f"No se encontró el vault en '{path}'. Por favor, ejecuta 'vault init' primero."
        )
        return
    except InvalidTag:
        # Bad master password
        count = record_fail(path)
        if count >= _MAX_ATTEMPTS:
            # Wipe vault and reset failure count
            Path(path).unlink(missing_ok=True)
            clear_fail(path)
            click.echo(
                "Demasiados intentos fallidos; el vault ha sido eliminado por seguridad."
            )
        else:
            left = _MAX_ATTEMPTS - count
            click.echo(f"Contraseña maestra incorrecta. Te quedan {left} intentos.")
        return

    # Buscar entrada por nombre
    entry = next((e for e in entries if e["name"] == entry_name), None)
    if not entry:
        click.echo(f"Entrada '{entry_name}' no encontrada.")
        return

    # Mostrar datos
    created = datetime.datetime.fromtimestamp(entry["timestamp"]).isoformat(
        sep=" ", timespec="seconds"
    )
    click.echo(f"Nombre:    {entry['name']}")
    click.echo(f"Usuario:   {entry['username']}")
    click.echo(f"Password:  {entry['password']}")
    click.echo(f"Nota:      {entry['note'] or '-'}")
    click.echo(f"Creado:    {created}")


@cli.command(name="list")
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
def list_entries(path):
    """
    Lista todas las entradas del vault con nombre y fecha de creación.
    """
    password = get_master_password()
    try:
        entries = load_entries(path, password)
        clear_fail(path)
    except FileNotFoundError:
        click.echo(
            f"No se encontró el vault en '{path}'. Por favor, ejecuta 'vault init' primero."
        )
        return
    except InvalidTag:
        # Bad master password
        count = record_fail(path)
        if count >= _MAX_ATTEMPTS:
            # Wipe vault and reset failure count
            Path(path).unlink(missing_ok=True)
            clear_fail(path)
            click.echo(
                "Demasiados intentos fallidos; el vault ha sido eliminado por seguridad."
            )
        else:
            left = _MAX_ATTEMPTS - count
            click.echo(f"Contraseña maestra incorrecta. Te quedan {left} intentos.")
        return

    if not entries:
        click.echo("No hay entradas en el vault.")
        return

    # Encabezado
    click.echo(f"{'Nombre':<20} {'Creado':<20}")
    click.echo("-" * 42)
    for e in entries:
        created = datetime.datetime.fromtimestamp(e["timestamp"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        click.echo(f"{e['name']:<20} {created:<20}")


# Nuevo comando: remove
@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
@click.option(
    "--name",
    "entry_name",
    required=True,
    help="Identificador único de la entrada a eliminar",
)
def remove(path, entry_name):
    """
    Elimina una entrada del vault.
    """
    password = get_master_password()
    # Cargar entradas existentes
    try:
        entries = load_entries(path, password)
        clear_fail(path)
    except FileNotFoundError:
        click.echo(
            f"No se encontró el vault en '{path}'. Por favor, ejecuta 'vault init' primero."
        )
        return
    except InvalidTag:
        # Bad master password
        count = record_fail(path)
        if count >= _MAX_ATTEMPTS:
            # Wipe vault and reset failure count
            Path(path).unlink(missing_ok=True)
            clear_fail(path)
            click.echo(
                "Demasiados intentos fallidos; el vault ha sido eliminado por seguridad."
            )
        else:
            left = _MAX_ATTEMPTS - count
            click.echo(f"Contraseña maestra incorrecta. Te quedan {left} intentos.")
        return

    # Verificar existencia
    if not any(e["name"] == entry_name for e in entries):
        click.echo(f"Entrada '{entry_name}' no encontrada.")
        return

    # Filtrar y guardar
    new_entries = [e for e in entries if e["name"] != entry_name]
    save_entries(path, password, new_entries)

    click.echo(f"Entrada '{entry_name}' eliminada correctamente.")


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado de origen")
@click.option(
    "--file", "dest_path", required=True, help="Ruta de destino para exportar el vault"
)
def export(path, dest_path):
    """
    Exporta el vault cifrado a otro fichero, validando la contraseña maestra.
    """
    password = get_master_password()
    # Verificar vault existente y contraseña correcta
    try:
        _ = load_entries(path, password)
    except FileNotFoundError:
        click.echo(
            f"No se encontró el vault en '{path}'. Por favor, ejecuta 'vault init' primero."
        )
        return
    except InvalidTag:
        click.echo("Contraseña maestra incorrecta.")
        return

    # Copiar fichero cifrado
    shutil.copy2(path, dest_path)
    click.echo(f"Vault exportado a '{dest_path}' correctamente.")


@cli.command(name="import")
@click.option(
    "--path", default="vault.dat", help="Ruta destino donde se importará el vault"
)
@click.option("--file", "src_path", required=True, help="Fichero cifrado a importar")
def import_vault(path, src_path):
    """
    Importa un vault cifrado desde otro fichero.
    """
    # Verificar fichero de origen
    if not os.path.exists(src_path):
        click.echo(f"No se encontró el fichero de importación en '{src_path}'.")
        return

    # Copiar fichero de origen
    shutil.copy2(src_path, path)
    click.echo(f"Vault importado desde '{src_path}' a '{path}' correctamente.")


@cli.command()
@click.option(
    "--shares", type=int, required=True, help="Número total de shares a generar"
)
@click.option(
    "--threshold",
    type=int,
    required=True,
    help="Número mínimo de shares para recuperar",
)
def backup(shares, threshold):
    """
    Genera N shares de la contraseña maestra, recuperables con K de ellas (Shamir).
    """
    # Obtener contraseña maestra validada
    master_pw = get_master_password()
    # Dividir en shares
    parts = split_secret(master_pw, shares, threshold)
    click.echo("Shares generadas (guárdalas de forma segura):")
    for part in parts:
        click.echo(part)


@cli.command()
@click.option(
    "--share",
    "shares",
    multiple=True,
    required=True,
    help="Shares para recuperar la contraseña",
)
def recover(shares):
    """
    Recupera la contraseña maestra a partir de shares (Shamir).
    """
    try:
        master_pw = recover_secret(list(shares))
    except Exception as e:
        click.echo(f"Error al recuperar el secreto: {e}")
        return
    # Guardar nueva sesión y borrar contador de fallos
    save_session(SESSION_PATH, master_pw.encode())
    clear_fail("vault.dat")
    click.echo("Contraseña maestra recuperada exitosamente:")
    click.echo(master_pw)


if __name__ == "__main__":
    cli()
