from click.testing import CliRunner
from vault.cli import cli


def test_pwned_safe(monkeypatch):
    runner = CliRunner()

    # Simular respuesta segura
    class Resp:
        status_code = 200
        text = "ABCDEF1234567890:2\nZZZZZZZZZZZZZZZZ:1"

    monkeypatch.setattr("requests.get", lambda url, timeout=5: Resp())
    result = runner.invoke(cli, ["pwned"], input="contraseñasegura\n")
    assert result.exit_code == 0
    assert "NO aparece" in result.output


def test_pwned_compromised(monkeypatch):
    runner = CliRunner()

    class Resp:
        status_code = 200
        # El hash SHA1 de 'test' es A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        # Prefijo: A94A8, Sufijo: FE5CCB19BA61C4C0873D391E987982FBBD3
        text = "FE5CCB19BA61C4C0873D391E987982FBBD3:42\nZZZZZZZZZZZZZZZZ:1"

    monkeypatch.setattr("requests.get", lambda url, timeout=5: Resp())
    result = runner.invoke(cli, ["pwned", "test"])
    assert result.exit_code == 0
    assert "ALERTA" in result.output or "veces en filtraciones" in result.output
