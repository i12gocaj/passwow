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
- **Recuperación de clave maestra** mediante Shamir’s Secret Sharing con comandos `backup` y `recover`.
- **Auto-lock**: la sesión de la contraseña maestra se mantiene activa durante un tiempo configurable (por defecto 5 min), tras el cual se vuelve a solicitar.
- Protección anti-brute-force: 5 intentos de contraseña maestra, luego auto-wipe del vault.
- Tests completos con >80% de cobertura de código.
- Análisis estático de seguridad con Bandit sin vulnerabilidades detectadas.
- **Benchmark de rendimiento**: script `scripts/benchmark.py` para medir tiempos de desbloqueo.
- **Fuzz testing**: pruebas con Hypothesis para validar almacenamiento y recuperación con datos aleatorios.
- **Autocompletado**: comando `completion` para generar scripts de autocompletion en Bash, Zsh y Fish.

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

### Backup y recuperación (Shamir’s Secret Sharing)

Para generar *n* shares y un umbral *k*:
```bash
poetry run python -m vault.cli backup --shares 5 --threshold 3
```
Esto imprimirá 5 líneas con `id-hexdata`. Para recuperar la contraseña con cualquier combinación de 3 shares:
```bash
poetry run python -m vault.cli recover \
  --share "1-<hexdata>" \
  --share "4-<hexdata>" \
  --share "5-<hexdata>"
```

### Auto-lock por inactividad

Una vez desbloqueado (por ejemplo tras `add`, `get`, etc.), la sesión de la contraseña maestra se guarda en `~/.passwow/session.json`.  
Si transcurren más de 5 min sin usar comandos, la sesión caduca y el siguiente comando volverá a pedir la contraseña maestra.

### Autocompletado de comandos

Puedes habilitar autocompletado para tu CLI en tu shell favorito siguiendo estos pasos:

1. **Instalar la dependencia** (solo si no lo has hecho):
   ```bash
   poetry add click-completion --dev
   ```

2. **Generar el script** de autocompletado para tu shell:
   
   - **Bash**:
     ```bash
     mkdir -p completions
     poetry run vault completion bash > completions/vault.bash
     ```
   - **Zsh**:
     ```bash
     mkdir -p completions
     poetry run vault completion zsh > completions/_vault
     ```
   - **Fish**:
     ```bash
     mkdir -p completions
     poetry run vault completion fish > completions/vault.fish
     ```

3. **Instalar el script** en tu configuración de shell:

   - **Bash**:  
     Añade en tu `~/.bashrc`:
     ```bash
     source /ruta/a/tu/proyecto/completions/vault.bash
     ```
     Luego recarga:
     ```bash
     source ~/.bashrc
     ```

   - **Zsh**:  
     Añade en tu `~/.zshrc`:
     ```zsh
     fpath=(/ruta/a/tu/proyecto/completions $fpath)
     autoload -Uz compinit && compinit
     ```
     Luego recarga:
     ```bash
     source ~/.zshrc
     ```

   - **Fish**:  
     Copia el script a tu carpeta de completions:
     ```bash
     cp completions/vault.fish ~/.config/fish/completions/
     ```
     Luego abre una nueva sesión de Fish.

4. **Probar el autocompletado**:
   Abre una nueva terminal y escribe:
   ```bash
   vault <TAB><TAB>
   ```
   Deberías ver sugerencias de todos los comandos y opciones disponibles.

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