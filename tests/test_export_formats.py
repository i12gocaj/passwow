from click.testing import CliRunner

from vault.cli import cli

import csv
import json


def test_export_json_and_csv(tmp_path):
    runner = CliRunner()
    vault_file = tmp_path / "vault_exportf.dat"
    pw = "pwexport"
    runner.invoke(cli, ["init", "--path", str(vault_file)], input=f"{pw}\n{pw}\n")
    runner.invoke(
        cli,
        ["add", "--path", str(vault_file), "--name", "e1", "--user", "u1"],
        input=f"{pw}\npass1\npass1\n",
    )
    # Exportar JSON
    json_file = tmp_path / "vault.json"
    result_json = runner.invoke(
        cli,
        [
            "export",
            "--path",
            str(vault_file),
            "--file",
            str(json_file),
            "--format",
            "json",
        ],
        input=f"{pw}\n",
    )
    assert result_json.exit_code == 0
    assert json_file.exists()
    data = json.loads(json_file.read_text())
    assert data[0]["name"] == "e1"
    # Exportar CSV
    csv_file = tmp_path / "vault.csv"
    result_csv = runner.invoke(
        cli,
        [
            "export",
            "--path",
            str(vault_file),
            "--file",
            str(csv_file),
            "--format",
            "csv",
        ],
        input=f"{pw}\n",
    )
    assert result_csv.exit_code == 0
    assert csv_file.exists()
    with open(csv_file) as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["name"] == "e1"
