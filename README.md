# passwow

[![CI](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml/badge.svg)](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)]()
[![Security](https://img.shields.io/badge/security-bandit_passed-green)]()

Gestor de contraseñas **local**, **minimalista** y **muy seguro**, basado en AES-256 GCM y derivación de clave con Scrypt.  
Incluye tanto una interfaz de línea de comandos (CLI) como una **aplicación gráfica (GUI) para macOS** para gestionar tus contraseñas de forma segura y flexible.

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
- **Protección contra manipulación**:
  - Verificación de integridad mediante checksum (SHA-256) para el archivo del vault.
  - Verificación de integridad mediante checksum (SHA-256) para el archivo de sesión.
  - Permisos de archivo restrictivos (600) para el vault, archivo de sesión, contador de fallos y checksums.
  - El contador de intentos fallidos se almacena ahora en el directorio `~/.passwow/` para evitar su eliminación accidental junto con el vault.
- **Borrado seguro**: el comando `delete` sobrescribe el vault y archivos sensibles antes de eliminarlos.
- **Cambio de contraseña maestra**: comando `changepw` para rotar la clave sin perder datos.
- **Exportación flexible**: comando `export` permite exportar el vault en formato cifrado, JSON o CSV para interoperabilidad o auditoría.
- **Comprobador de contraseñas comprometidas**: comando `pwned` consulta la API de HaveIBeenPwned para saber si una contraseña ha sido filtrada.
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

## Aplicación gráfica para macOS

Además de la CLI, passwow incluye una **aplicación gráfica (GUI) para macOS** empaquetada con PyInstaller.

### Ejecutar la app gráfica

Tras descargar o compilar el bundle, puedes abrir la app desde Finder o desde terminal:

```bash
open dist/gui.app
```

La app utiliza el mismo vault seguro que la CLI y permite gestionar tus contraseñas de forma visual.

### Empaquetar la app tú mismo

Si modificas el código y quieres volver a generar la app:

1. Instala PyInstaller:
   ```bash
   poetry run pip install pyinstaller
   ```
2. Ejecuta el empaquetado:
   ```bash
   poetry run pyinstaller gui.spec
   ```
   Esto generará `dist/gui.app` y el ejecutable standalone `dist/gui`.

- El icono personalizado está en `icon.icns` y se incluye automáticamente.
- El vault y su checksum se guardan junto al ejecutable.

---

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
poetry run python -m vault.cli export --path vault.dat --file backup.dat --format encrypted

# Importar vault cifrado
poetry run python -m vault.cli import --path vault.dat --file backup.dat
```

Ejemplos de uso de nuevas características:

```bash
# Borrado seguro del vault y archivos asociados
poetry run python -m vault.cli delete --path vault.dat

# Cambiar la contraseña maestra
poetry run python -m vault.cli changepw --path vault.dat

# Exportar vault a JSON o CSV
poetry run python -m vault.cli export --path vault.dat --file backup.json --format json
poetry run python -m vault.cli export --path vault.dat --file backup.csv --format csv

# Comprobar si una contraseña ha sido filtrada (HaveIBeenPwned)
poetry run python -m vault.cli pwned "miclaveultrasegura"
# O interactivo (no se muestra en pantalla):
poetry run python -m vault.cli pwned
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

Una vez desbloqueado (por ejemplo tras `add`, `get`, etc.), la sesión de la contraseña maestra se guarda en `~/.passwow/session.json`. Este archivo ahora incluye un checksum para detectar manipulaciones.  
Si transcurren más de 5 min sin usar comandos, la sesión caduca y el siguiente comando volverá a pedir la contraseña maestra.

## Cobertura de tests y ramas defensivas

El proyecto cuenta con una suite de tests exhaustiva que cubre todos los comandos, errores, condiciones límite y defensivas. El coverage real es superior al 96% y todas las rutas de código relevantes para la seguridad y la funcionalidad están cubiertas.

Las únicas líneas no cubiertas corresponden a ramas imposibles de ejecutar en un entorno de test estándar, como:
- Protecciones del tipo `if __name__ == "__main__"` (ejecución directa del CLI).
- Returns tempranos silenciosos o defensivos que solo se activan en condiciones anómalas o de corrupción extrema.
- Excepciones de librerías externas que no se pueden forzar sin manipulación interna o monkeypatching inseguro.

Esto significa que el coverage reportado es el máximo alcanzable en condiciones reales y seguras. No quedan prints de depuración ni ramas sin cubrir que sean relevantes para la robustez, seguridad o experiencia de usuario.

### Protección contra Manipulación y Anti-Brute-Force Mejorada

- **Integridad del Vault**: Cada vez que el vault (`vault.dat` por defecto) es modificado (ej. `add`, `remove`, `init`) o accedido (`get`, `list`, `export`), se calcula y guarda un checksum (SHA-256) en un archivo acompañante (ej. `vault.dat.checksum`). Antes de cada operación de lectura o modificación, este checksum se verifica. Si hay una discrepancia, la operación se aborta para prevenir el uso de un vault corrupto o manipulado. Al exportar e importar, el archivo de checksum también se transfiere.
- **Integridad del Archivo de Sesión**: El archivo `~/.passwow/session.json` que almacena la clave maestra temporalmente también está protegido por un checksum interno. Si el archivo es modificado externamente, la sesión se invalida.
- **Contador de Intentos Fallidos Seguro**: El archivo que registra los intentos fallidos de ingreso de la contraseña maestra (ej. `vault.dat.fail`) ha sido movido al directorio `~/.passwow/`. Esto previene que un atacante pueda restaurar una copia del vault y resetear el contador simplemente borrando el archivo `.fail` junto al vault.
- **Permisos Restrictivos**: Todos los archivos sensibles (`vault.dat`, `vault.dat.checksum`, `~/.passwow/session.json`, `~/.passwow/vault.dat.fail`) se guardan con permisos de archivo `600` (lectura/escritura solo para el propietario) siempre que sea posible en el sistema operativo.
- **Prevención de Restauración Post-Wipe**: Si el vault es eliminado debido a demasiados intentos fallidos (auto-wipe), tanto el archivo del vault como su checksum son eliminados. Intentar restaurar una copia del vault (`vault.dat`) sin su correspondiente y válido archivo de checksum (o con uno que no coincida) resultará en un fallo de verificación de integridad, impidiendo el acceso. La importación de un vault también verifica su integridad si el archivo de checksum está presente.

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

## ¿Qué es `vault.dat.checksum`?

El archivo `vault.dat.checksum` almacena un hash SHA-256 del contenido cifrado de tu vault (`vault.dat`). Sirve para verificar la integridad del vault y detectar manipulaciones o corrupción antes de cada operación. Si el hash no coincide, el acceso se bloquea para proteger tus datos.

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

---

## Publicación y comunidad

Este repositorio está listo para publicación pública en GitHub. Puedes contribuir, reportar issues o sugerir mejoras:

- Abre un [Issue](https://github.com/i12gocaj/passwow/issues) para reportar bugs o solicitar nuevas funciones.
- Haz un fork y envía un Pull Request para contribuir código.
- Consulta la documentación y ejemplos en este README.

### ¿Cómo usar la CLI y la app gráfica?

- **CLI:**
  - Ejecuta comandos como `poetry run python -m vault.cli ...` o instala el paquete y usa `vault ...` directamente.
  - Soporta autocompletado, backup, recuperación, exportación/importación, y protección avanzada.
- **App gráfica (macOS):**
  - Ejecuta `open dist/gui.app` o haz doble clic en el Finder.
  - Permite gestionar el vault de forma visual, con las mismas garantías de seguridad.

### Soporte

- [Documentación actualizada en el README](https://github.com/i12gocaj/passwow#readme)
- Contacto: i12gocaj@uco.es

---