# passwow

[![CI](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml/badge.svg)](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen)]()
[![Security](https://img.shields.io/badge/security-bandit_passed-green)]()

Gestor de contraseñas **local**, **minimalista** y **muy seguro**, basado en AES-256 GCM y derivación de clave con Scrypt.  
Interfaz de línea de comandos (CLI) con comandos para inicializar, añadir, listar, obtener, eliminar, exportar e importar vaults cifrados.

## Características

- Cifrado AES-256 GCM y derivación de clave maestra con Scrypt (parametrización segura).
- Vault local en disco con opción de sincronización manual (`export`/`import`).
- Comandos CLI:  
  - `init` — Inicializar vault.  
  - `add` — Añadir nueva entrada.  
  - `get` — Recuperar entrada.  
  - `list` — Listar todas las entradas.  
  - `remove` — Eliminar entrada.  
  - `export` — Exportar vault cifrado.  
  - `import` — Importar vault cifrado.  
- Protección anti-brute-force: 5 intentos de contraseña maestra, luego auto-wipe del vault.
- Tests completos con >80% de cobertura de código.
- Análisis estático de seguridad con Bandit sin vulnerabilidades detectadas.

## Instalación

Requisitos: Python 3.10+ y [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/i12gocaj/passwow.git
cd passwow
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## Uso

Ejecuta los comandos desde Poetry o directamente con Python:

```bash
# Inicializar un nuevo vault
poetry run python -m vault.cli init --path vault.dat

# Añadir una entrada
poetry run python -m vault.cli add --path vault.dat --name ejemplo --user miusuario

# Listar entradas
poetry run python -m vault.cli list --path vault.dat

# Obtener datos de una entrada
poetry run python -m vault.cli get --path vault.dat --name ejemplo

# Eliminar una entrada
poetry run python -m vault.cli remove --path vault.dat --name ejemplo

# Exportar vault cifrado
poetry run python -m vault.cli export --path vault.dat --file backup.dat

# Importar vault cifrado
poetry run python -m vault.cli import --path vault.dat --file backup.dat
```

## Desarrollo

Activa el entorno virtual de Poetry y ejecuta tests:

```bash
poetry shell
pytest --maxfail=1 --disable-warnings -q
```

- Ver cobertura:
  ```bash
  pytest --cov=src/vault --cov-report=term-missing
  ```
- Comprueba el estilo de código:
  ```bash
  poetry run black --check .
  poetry run flake8 .
  ```
- Escanea seguridad:
  ```bash
  poetry run bandit -r src/vault
  ```

## Contribuir

1. Haz fork del repositorio.  
2. Crea una rama de feature: `git checkout -b feature/nueva-funcion`.  
3. Asegura que pasen todos los tests y cumplen linters.  
4. Abre un Pull Request.

## Licencia

Este proyecto está bajo la licencia MIT.  