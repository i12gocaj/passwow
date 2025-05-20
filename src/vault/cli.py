import click
import click_completion

import os
import json
import time
import datetime

import shutil
import hashlib
import secrets
import string
import requests  # Para el comando pwned
import csv  # Para exportación CSV

from vault.crypto import derive_key, encrypt_data, _SALT_SIZE
from vault.storage import load_entries, save_entries

from pathlib import Path
from cryptography.exceptions import InvalidTag

import vault.session  # Modificado: Importar el módulo en lugar de la constante

try:
    import pyperclip

    HAS_CLIPBOARD = True
except ImportError:
    HAS_CLIPBOARD = False

click_completion.init()

_MAX_ATTEMPTS = 5
_VAULT_INTEGRITY_FILE_SUFFIX = ".checksum"


def _get_vault_integrity_path(vault_path: str) -> Path:
    """Devuelve la ruta al archivo de integridad del vault."""
    return Path(vault_path).with_suffix(
        Path(vault_path).suffix + _VAULT_INTEGRITY_FILE_SUFFIX
    )


def _calculate_vault_checksum(vault_path: str) -> str:
    """Calcula un checksum SHA-256 para el contenido del vault."""
    vault_content = Path(vault_path).read_bytes()
    return hashlib.sha256(vault_content).hexdigest()


def _write_vault_checksum(vault_path: str):
    """Escribe el checksum del vault a su archivo de integridad."""
    checksum = _calculate_vault_checksum(vault_path)
    integrity_file = _get_vault_integrity_path(vault_path)
    integrity_file.write_text(checksum)
    integrity_file.chmod(0o600)  # Permisos restrictivos


def _verify_vault_checksum(vault_path: str) -> bool:
    """Verifica la integridad del vault comparando su checksum actual con el almacenado."""
    integrity_file = _get_vault_integrity_path(vault_path)
    if not integrity_file.exists():
        # Si no hay checksum, no se puede verificar. Podría ser un vault nuevo o importado sin checksum.
        # Considerar esto como válido para permitir la inicialización o primera carga.
        return True

    stored_checksum = integrity_file.read_text()
    current_checksum = _calculate_vault_checksum(vault_path)
    return stored_checksum == current_checksum


def _fail_file(path: str) -> Path:
    """Return the path for the failure count file."""
    # Almacenar el contador de fallos en el directorio de sesión para mayor seguridad
    session_dir = vault.session.DEFAULT_SESSION_DIR
    session_dir.mkdir(parents=True, exist_ok=True)  # Asegura que el directorio exista
    return session_dir / (Path(path).name + ".fail")


def record_fail(path: str) -> int:
    """Increment and return the number of failed attempts for this vault."""
    fpath = _fail_file(path)
    fpath.parent.mkdir(parents=True, exist_ok=True)  # Asegurar que el directorio exista
    count = int(fpath.read_text() or "0") if fpath.exists() else 0
    count += 1
    fpath.write_text(str(count))
    fpath.chmod(0o600)  # Permisos restrictivos
    return count


def clear_fail(path: str):
    """Clear the failure count for this vault."""
    fpath = _fail_file(path)
    if fpath.exists():
        fpath.unlink()


# --- Utilidad para borrado seguro ---
def secure_delete_file(path: Path, passes: int = 3):
    """Sobrescribe el archivo con datos aleatorios antes de eliminarlo."""
    if not path.exists() or not path.is_file():
        return
    length = path.stat().st_size
    try:
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except Exception:
        # Si falla, intentar al menos borrar
        try:
            path.unlink()
        except Exception as e:
            click.secho(f"[ADVERTENCIA] No se pudo eliminar {path}: {e}", fg="yellow")


@click.group()
def cli():
    """Gestor de contraseñas local."""
    pass


# Comando explícito para autocompletado
@cli.command()
@click.argument(
    "shell",
    required=True,
    type=click.Choice(["bash", "zsh", "fish", "powershell", "auto"]),
)
def completion(shell):
    """
    Genera el script de autocompletado para el shell dado.
    """
    code = click_completion.get_code(shell)
    click.echo(code)


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
    vault_p = Path(path)
    if vault_p.exists():
        click.secho(
            f"[!] El vault '{path}' ya existe. Si quieres reiniciarlo, elimínalo primero.",
            fg="yellow",
        )
        return

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

    _write_vault_checksum(path)  # Escribir checksum inicial
    vault_p.chmod(0o600)  # Permisos restrictivos para el vault

    clear_fail(path)

    click.secho(
        f"✅ Vault inicializado correctamente en '{path}'. ¡Listo para usar!",
        fg="green",
        bold=True,
    )


def _handle_load_entries(path: str, password: str):
    """Función helper para cargar entradas y manejar errores comunes."""
    if not Path(path).exists():
        click.secho(
            f"[!] No se encontró el vault en '{path}'. Usa 'vault init' para crearlo.",
            fg="red",
            bold=True,
        )
        return None

    if not _verify_vault_checksum(path):
        click.secho(
            f"[ALERTA] El archivo del vault '{path}' parece haber sido manipulado o está corrupto. Operación abortada por seguridad.",
            fg="red",
            bold=True,
        )
        return None

    try:
        entries = load_entries(path, password)
        clear_fail(path)
        _write_vault_checksum(path)
        return entries
    except InvalidTag:
        count = record_fail(path)
        if count >= _MAX_ATTEMPTS:
            Path(path).unlink(missing_ok=True)
            _get_vault_integrity_path(path).unlink(missing_ok=True)
            clear_fail(path)
            click.secho(
                "[BLOQUEO] Demasiados intentos fallidos. El vault ha sido eliminado por seguridad.",
                fg="red",
                bold=True,
            )
        else:
            left = _MAX_ATTEMPTS - count
            click.secho(
                f"Contraseña maestra incorrecta. Te quedan {left} intento(s).",
                fg="yellow",
            )
        return None
    except Exception as e:
        click.secho(f"[ERROR] No se pudo abrir el vault: {e}", fg="red", bold=True)
        return None


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del fichero cifrado")
@click.option("--name", required=True, help="Identificador único de la entrada")
@click.option("--user", "username", required=True, help="Nombre de usuario/login")
@click.option("--note", default="", help="Nota opcional para la entrada")
@click.option(
    "--generate", is_flag=True, help="Genera una contraseña segura automáticamente"
)
def add(path, name, username, note, generate):
    """
    Añade una nueva entrada al vault. Usa --generate para crear una contraseña segura automáticamente.
    """
    password = click.prompt("Contraseña maestra", hide_input=True)
    entries = _handle_load_entries(path, password)
    if entries is None:
        return

    if generate:
        length = click.prompt(
            "Longitud de la contraseña generada", default=20, type=int
        )
        alphabet = string.ascii_letters + string.digits + string.punctuation
        entry_pass = "".join(secrets.choice(alphabet) for _ in range(length))
        click.secho(f"Contraseña generada: {entry_pass}", fg="cyan")
        if HAS_CLIPBOARD:
            pyperclip.copy(entry_pass)
            click.secho("(Copiada al portapapeles)", fg="green")
    else:
        entry_pass = click.prompt(
            "Contraseña para la entrada",
            hide_input=True,
            confirmation_prompt=True,
        )

    new_entry = {
        "name": name,
        "username": username,
        "password": entry_pass,
        "note": note,
        "timestamp": int(time.time()),
    }

    entries.append(new_entry)
    save_entries(path, password, entries)
    _write_vault_checksum(path)

    click.secho(f"✅ Entrada '{name}' añadida correctamente.", fg="green", bold=True)


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
    password = click.prompt("Contraseña maestra", hide_input=True)
    entries = _handle_load_entries(path, password)
    if entries is None:
        return

    # Buscar entrada por nombre
    entry = next((e for e in entries if e["name"] == entry_name), None)
    if not entry:
        click.secho(
            f"[!] Entrada '{entry_name}' no encontrada en el vault.", fg="yellow"
        )
        return

    # Mostrar datos
    created = datetime.datetime.fromtimestamp(entry["timestamp"]).isoformat(
        sep=" ", timespec="seconds"
    )
    click.secho("\n--- Detalles de la entrada ---", fg="cyan", bold=True)
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
    password = click.prompt("Contraseña maestra", hide_input=True)
    entries = _handle_load_entries(path, password)
    if entries is None:
        return

    if not entries:
        click.secho("No hay entradas guardadas en el vault.", fg="yellow")
        return

    click.secho(f"{'Nombre':<20} {'Creado':<20}", fg="cyan", bold=True)
    click.secho("-" * 42, fg="cyan")
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
    password = click.prompt("Contraseña maestra", hide_input=True)
    entries = _handle_load_entries(path, password)
    if entries is None:
        return

    if not any(e["name"] == entry_name for e in entries):
        click.secho(
            f"[!] Entrada '{entry_name}' no encontrada en el vault.", fg="yellow"
        )
        return

    new_entries = [e for e in entries if e["name"] != entry_name]
    save_entries(path, password, new_entries)
    _write_vault_checksum(path)

    click.secho(
        f"✅ Entrada '{entry_name}' eliminada correctamente.", fg="green", bold=True
    )


# --- Comando para cambiar la contraseña maestra ---
@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del vault a modificar")
def changepw(path):
    """
    Cambia la contraseña maestra del vault de forma segura.
    """
    if not Path(path).exists():
        click.secho(f"[!] No se encontró el vault en '{path}'.", fg="red", bold=True)
        return
    old_pw = click.prompt("Contraseña maestra actual", hide_input=True)
    entries = _handle_load_entries(path, old_pw)
    if entries is None:
        return
    new_pw = click.prompt(
        "Nueva contraseña maestra", hide_input=True, confirmation_prompt=True
    )
    save_entries(path, new_pw, entries)
    _write_vault_checksum(path)
    click.secho("✅ Contraseña maestra cambiada correctamente.", fg="green", bold=True)


# --- Exportación a JSON/CSV ---
@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del vault de origen")
@click.option(
    "--file", "dest_path", required=True, help="Ruta de destino para exportar"
)
@click.option(
    "--format",
    type=click.Choice(["bin", "json", "csv"]),
    default="bin",
    help="Formato de exportación: bin (cifrado), json, csv",
)
def export(path, dest_path, format):
    """
    Exporta el vault en formato cifrado (bin), JSON o CSV.
    """
    password = click.prompt("Contraseña maestra", hide_input=True)
    if not Path(path).exists():
        click.secho(f"[!] No se encontró el vault en '{path}'.", fg="red", bold=True)
        return
    if not _verify_vault_checksum(path):
        click.secho(
            f"[ALERTA] El archivo del vault '{path}' parece haber sido manipulado. Exportación cancelada por seguridad.",
            fg="red",
            bold=True,
        )
        return
    try:
        entries = load_entries(path, password)
    except InvalidTag:
        click.secho("Contraseña maestra incorrecta. No se puede exportar.", fg="yellow")
        return
    except Exception as e:
        click.secho(f"[ERROR] No se pudo verificar el vault: {e}", fg="red", bold=True)
        return
    if format == "bin":
        try:
            shutil.copy2(path, dest_path)
            Path(dest_path).chmod(0o600)
            checksum_path = _get_vault_integrity_path(path)
            dest_checksum_path = _get_vault_integrity_path(dest_path)
            if checksum_path.exists():
                shutil.copy2(checksum_path, dest_checksum_path)
                dest_checksum_path.chmod(0o600)
            else:
                _write_vault_checksum(dest_path)
            click.secho(
                f"✅ Vault exportado correctamente a '{dest_path}'.",
                fg="green",
                bold=True,
            )
        except Exception as e:
            click.secho(f"[ERROR] durante la exportación: {e}", fg="red", bold=True)
    elif format == "json":
        try:
            with open(dest_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
            Path(dest_path).chmod(0o600)
            click.secho(
                f"✅ Vault exportado en JSON a '{dest_path}'.", fg="green", bold=True
            )
        except Exception as e:
            click.secho(f"[ERROR] al exportar JSON: {e}", fg="red", bold=True)
    elif format == "csv":
        try:
            with open(dest_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["name", "username", "password", "note", "timestamp"]
                )
                writer.writeheader()
                for entry in entries:
                    writer.writerow(entry)
            Path(dest_path).chmod(0o600)
            click.secho(
                f"✅ Vault exportado en CSV a '{dest_path}'.", fg="green", bold=True
            )
        except Exception as e:
            click.secho(f"[ERROR] al exportar CSV: {e}", fg="red", bold=True)


# --- Comando para comprobar contraseñas comprometidas (HaveIBeenPwned) ---
@cli.command()
@click.argument("password", required=False)
def pwned(password):
    """
    Comprueba si una contraseña ha sido comprometida usando la API de HaveIBeenPwned.
    Si no se pasa como argumento, la pide de forma oculta.
    """
    if not password:
        password = click.prompt("Contraseña a comprobar", hide_input=True)
    sha1 = (
        hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    )  # noqa: B324
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code != 200:
            click.secho(
                "[ERROR] No se pudo consultar la API de HaveIBeenPwned.", fg="red"
            )
            return
        hashes = (line.split(":") for line in resp.text.splitlines())
        for suf, count in hashes:
            if suf == suffix:
                click.secho(
                    f"[ALERTA] ¡Esta contraseña ha aparecido {count} veces en filtraciones!",
                    fg="red",
                    bold=True,
                )
                return
        click.secho(
            "✅ Esta contraseña NO aparece en la base de datos de filtraciones conocidas.",
            fg="green",
        )
    except Exception as e:
        click.secho(f"[ERROR] No se pudo consultar la API: {e}", fg="red")


@cli.command()
@click.option("--path", default="vault.dat", help="Ruta del vault a eliminar")
def delete(path):
    """
    Elimina de forma segura el vault, su checksum, contador de fallos y sesión activa.
    """
    vault_p = Path(path)
    checksum_p = _get_vault_integrity_path(path)
    fail_p = _fail_file(path)
    session_p = vault.session.DEFAULT_SESSION_DIR / "session.json"

    if not vault_p.exists():
        click.secho(f"[!] No se encontró el vault en '{path}'.", fg="red", bold=True)
        return

    click.secho(
        f"Vas a eliminar DEFINITIVAMENTE el vault '{path}' y todos sus datos asociados.",
        fg="red",
        bold=True,
    )
    confirm = click.prompt(
        "¿Estás seguro? Escribe 'BORRAR' para confirmar", default="no"
    )
    if confirm != "BORRAR":
        click.secho("Operación cancelada.", fg="yellow")
        return

    # Borrado seguro
    for f in [vault_p, checksum_p, fail_p, session_p]:
        try:
            if f.exists() and f.is_file():
                secure_delete_file(f)
        except Exception as e:
            click.secho(f"[ADVERTENCIA] No se pudo eliminar {f}: {e}", fg="yellow")
    click.secho(
        "✅ Vault y archivos asociados eliminados de forma segura.",
        fg="green",
        bold=True,
    )


# --- Comando para importar vaults ---
@cli.command(name="import")
@click.option(
    "--path", default="vault.dat", help="Ruta destino donde se importará el vault"
)
@click.option("--file", "src_path", required=True, help="Fichero cifrado a importar")
def import_vault(path, src_path):
    """
    Importa un vault cifrado desde otro fichero, incluyendo su checksum si existe.
    """
    src_vault_p = Path(src_path)
    dest_vault_p = Path(path)

    if not src_vault_p.exists():
        click.secho(
            f"[!] No se encontró el fichero de importación en '{src_path}'.",
            fg="red",
            bold=True,
        )
        return 0

    src_checksum_p = _get_vault_integrity_path(src_path)
    if src_checksum_p.exists():
        if not _verify_vault_checksum(src_path):
            click.secho(
                f"[ALERTA] El archivo del vault de origen '{src_path}' parece manipulado. Importación cancelada por seguridad.",
                fg="red",
                bold=True,
            )
            return 0
    else:
        click.secho(
            f"[ADVERTENCIA] El vault de origen '{src_path}' no tiene archivo de checksum para verificar su integridad.",
            fg="yellow",
        )

    try:
        shutil.copy2(src_path, path)
        dest_vault_p.chmod(0o600)
        dest_checksum_p = _get_vault_integrity_path(path)
        if src_checksum_p.exists():
            shutil.copy2(src_checksum_p, dest_checksum_p)
            dest_checksum_p.chmod(0o600)
        else:
            _write_vault_checksum(path)
        clear_fail(path)
        click.secho(
            f"✅ Vault importado correctamente desde '{src_path}' a '{path}'.",
            fg="green",
            bold=True,
        )
        return 0
    except Exception as e:
        click.secho(f"[ERROR] durante la importación: {e}", fg="red", bold=True)
        return 0


if __name__ == "__main__":
    cli()
