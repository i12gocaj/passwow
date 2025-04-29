import os
import pytest
from click.testing import CliRunner
from vault.cli import cli


def test_init_creates_vault_file(tmp_path):
    # Use a temporary directory for the vault file
    runner = CliRunner()
    vault_file = tmp_path / "vault_test.dat"
    password = "testpassword"
    # Invoke the CLI 'init' command, simulating password entry twice (confirmation)
    result = runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{password}\n{password}\n"
    )
    # CLI should exit successfully
    assert result.exit_code == 0
    # Output should confirm vault initialization at the given path
    assert f"Vault inicializado en {vault_file}" in result.output
    # The vault file should exist and be non-empty
    assert vault_file.exists()
    assert vault_file.stat().st_size > 0
