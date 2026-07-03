# passwow

[![CI](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml/badge.svg)](https://github.com/i12gocaj/passwow/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)]()
[![Security](https://img.shields.io/badge/security-bandit_passed-green)]()

**Local**, **minimalist**, and security-focused password manager based on AES-256 GCM and Scrypt key derivation.

It includes both a command-line interface (CLI) and a **macOS graphical app (GUI)** for managing passwords securely and flexibly.

The CLI includes commands to initialize, add, list, retrieve, remove, export, and import encrypted vaults.

## Features

- AES-256 GCM encryption and master-key derivation with Scrypt using secure parameters.
- Local vault stored on disk, with manual synchronization through `export` / `import`.
- CLI commands:
  - `init` - Initialize a vault.
  - `add` - Add a new entry.
  - `get` - Retrieve an entry.
  - `list` - List all entries.
  - `remove` - Remove an entry.
  - `export` - Export an encrypted vault.
  - `import` - Import an encrypted vault.
- **Master-key recovery** through Shamir's Secret Sharing with `backup` and `recover`.
- **Auto-lock**: the master-password session remains active for a configurable time (5 minutes by default), then it is requested again.
- Anti-brute-force protection: 5 master-password attempts, then automatic vault wipe.
- **Tamper protection**:
  - Integrity verification through SHA-256 checksum for the vault file.
  - Integrity verification through SHA-256 checksum for the session file.
  - Restrictive file permissions (`600`) for the vault, session file, failure counter, and checksums.
  - The failed-attempt counter is stored in `~/.passwow/` to prevent accidental deletion together with the vault.
- **Secure deletion**: `delete` overwrites the vault and sensitive files before removing them.
- **Master-password rotation**: `changepw` rotates the key without losing data.
- **Flexible export**: `export` can produce encrypted, JSON, or CSV output for interoperability or auditing.
- **Compromised-password checker**: `pwned` queries the HaveIBeenPwned API to check whether a password has leaked.
- Test suite with more than 80% code coverage.
- Static security analysis with Bandit and no detected vulnerabilities.
- **Performance benchmark**: `scripts/benchmark.py` measures unlock times.
- **Fuzz testing** with Hypothesis to validate storage and retrieval with random data.
- **Shell completion**: `completion` generates autocomplete scripts for Bash, Zsh, and Fish.

## Installation

Requirements: Python 3.10+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/i12gocaj/passwow.git
cd passwow
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## macOS Graphical App

In addition to the CLI, passwow includes a **macOS graphical app (GUI)** packaged with PyInstaller.

### Running the GUI

After downloading or building the bundle, open the app from Finder or from the terminal:

```bash
open dist/gui.app
```

The app uses the same secure vault as the CLI and lets you manage passwords visually.

### Building the GUI Yourself

If you modify the code and want to rebuild the app:

1. Install PyInstaller:
   ```bash
   poetry run pip install pyinstaller
   ```
2. Run the packaging command:
   ```bash
   poetry run pyinstaller gui.spec
   ```
   This generates `dist/gui.app` and the standalone `dist/gui` executable.

- The custom icon is in `icon.icns` and is included automatically.
- The vault and checksum are stored next to the executable.

## Usage

Run commands through Poetry or directly with Python:

```bash
# Initialize a new vault
poetry run python -m vault.cli init --path vault.dat

# Add an entry
poetry run python -m vault.cli add --path vault.dat --name example --user myuser

# List entries
poetry run python -m vault.cli list --path vault.dat

# Retrieve entry data
poetry run python -m vault.cli get --path vault.dat --name example

# Remove an entry
poetry run python -m vault.cli remove --path vault.dat --name example

# Export encrypted vault
poetry run python -m vault.cli export --path vault.dat --file backup.dat --format encrypted

# Import encrypted vault
poetry run python -m vault.cli import --path vault.dat --file backup.dat
```

Examples for additional features:

```bash
# Secure deletion of the vault and related files
poetry run python -m vault.cli delete --path vault.dat

# Change the master password
poetry run python -m vault.cli changepw --path vault.dat

# Export vault to JSON or CSV
poetry run python -m vault.cli export --path vault.dat --file backup.json --format json
poetry run python -m vault.cli export --path vault.dat --file backup.csv --format csv

# Check whether a password has leaked (HaveIBeenPwned)
poetry run python -m vault.cli pwned "myultrasecurepassword"
# Or interactive mode (password is not shown on screen):
poetry run python -m vault.cli pwned
```

### Backup and Recovery (Shamir's Secret Sharing)

To generate *n* shares with threshold *k*:

```bash
poetry run python -m vault.cli backup --shares 5 --threshold 3
```

This prints 5 lines with `id-hexdata`. To recover the password with any combination of 3 shares:

```bash
poetry run python -m vault.cli recover \
  --share "1-<hexdata>" \
  --share "4-<hexdata>" \
  --share "5-<hexdata>"
```

### Auto-Lock on Inactivity

Once unlocked (for example after `add`, `get`, etc.), the master-password session is stored in `~/.passwow/session.json`. This file now includes a checksum to detect tampering.

If more than 5 minutes pass without using commands, the session expires and the next command asks for the master password again.

## Test Coverage and Defensive Branches

The project includes an extensive test suite covering all commands, errors, edge cases, and defensive conditions. Real coverage is above 96%, and all relevant code paths for security and functionality are covered.

The only uncovered lines are branches that cannot be executed in a standard test environment, such as:

- `if __name__ == "__main__"` guards for direct CLI execution.
- Silent or defensive early returns that only trigger under abnormal or extreme corruption conditions.
- External-library exceptions that cannot be forced without unsafe internal manipulation or monkeypatching.

That means the reported coverage is the maximum achievable under realistic and safe conditions. There are no debug prints or uncovered branches relevant to robustness, security, or user experience.

### Improved Tamper Protection and Anti-Brute-Force

- **Vault integrity**: whenever the vault (`vault.dat` by default) is modified (`add`, `remove`, `init`) or accessed (`get`, `list`, `export`), a SHA-256 checksum is calculated and stored in a companion file such as `vault.dat.checksum`. Before every read or write operation, that checksum is verified. If it does not match, the operation is aborted to prevent use of a corrupted or manipulated vault. During export/import, the checksum file is transferred too.
- **Session-file integrity**: `~/.passwow/session.json`, which temporarily stores the master key, is also protected by an internal checksum. If the file is externally modified, the session is invalidated.
- **Safe failed-attempt counter**: the file that tracks failed master-password attempts, such as `vault.dat.fail`, has been moved to `~/.passwow/`. This prevents an attacker from restoring a copy of the vault and resetting the counter by simply deleting the `.fail` file next to it.
- **Restrictive permissions**: sensitive files (`vault.dat`, `vault.dat.checksum`, `~/.passwow/session.json`, `~/.passwow/vault.dat.fail`) are saved with `600` permissions whenever the operating system allows it.
- **Post-wipe restore prevention**: if the vault is deleted due to too many failed attempts, both the vault file and its checksum are removed. Restoring a copy of `vault.dat` without a matching valid checksum, or with a mismatched checksum, fails integrity verification and blocks access. Vault import also verifies integrity when a checksum file is present.

### Shell Completion

Enable autocomplete for your favourite shell:

1. **Install the dependency** if you have not already:
   ```bash
   poetry add click-completion --dev
   ```

2. **Generate the completion script** for your shell:

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

3. **Install the script** in your shell configuration:

   - **Bash**:
     Add this to `~/.bashrc`:
     ```bash
     source /path/to/your/project/completions/vault.bash
     ```
     Then reload:
     ```bash
     source ~/.bashrc
     ```

   - **Zsh**:
     Add this to `~/.zshrc`:
     ```zsh
     fpath=(/path/to/your/project/completions $fpath)
     autoload -Uz compinit && compinit
     ```
     Then reload:
     ```bash
     source ~/.zshrc
     ```

   - **Fish**:
     Copy the script to your completions folder:
     ```bash
     cp completions/vault.fish ~/.config/fish/completions/
     ```
     Then open a new Fish session.

4. **Test completion**:
   Open a new terminal and type:
   ```bash
   vault <TAB><TAB>
   ```
   You should see suggestions for all available commands and options.

## What Is `vault.dat.checksum`?

The `vault.dat.checksum` file stores a SHA-256 hash of the encrypted vault content (`vault.dat`). It is used to verify vault integrity and detect tampering or corruption before every operation. If the hash does not match, access is blocked to protect your data.

## Development

Activate the Poetry environment and run tests:

```bash
poetry shell
pytest --maxfail=1 --disable-warnings -q
```

- Check coverage:
  ```bash
  pytest --cov=src/vault --cov-report=term-missing
  ```
- Check code style:
  ```bash
  poetry run black --check .
  poetry run flake8 .
  ```
- Run security scan:
  ```bash
  poetry run bandit -r src/vault
  ```

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/new-feature`.
3. Make sure all tests and linters pass.
4. Open a Pull Request.

## License

This project is licensed under the MIT License.

## Publication and Community

This repository is ready for public release on GitHub. You can contribute, report issues, or suggest improvements:

- Open an [Issue](https://github.com/i12gocaj/passwow/issues) to report bugs or request features.
- Fork the project and submit a Pull Request to contribute code.
- See this README for documentation and examples.

### How to Use the CLI and GUI

- **CLI:**
  - Run commands such as `poetry run python -m vault.cli ...`, or install the package and use `vault ...` directly.
  - Supports autocomplete, backup, recovery, export/import, and advanced protection.
- **macOS GUI:**
  - Run `open dist/gui.app` or double-click it in Finder.
  - Lets you manage the vault visually with the same security guarantees.

### Support

- [Updated documentation in the README](https://github.com/i12gocaj/passwow#readme)
- Contact: i12gocaj@uco.es
