from hypothesis import given, strategies as st, settings, HealthCheck
from click.testing import CliRunner
from vault.cli import cli
from vault.storage import save_entries, load_entries


@st.composite
def entry_strategy(draw):
    name = draw(st.text(min_size=1, max_size=20))
    username = draw(st.text(min_size=1, max_size=20))
    password = draw(st.text(min_size=1, max_size=50))
    note = draw(st.text(max_size=100))
    timestamp = draw(st.integers(min_value=0, max_value=2**31 - 1))
    return {
        "name": name,
        "username": username,
        "password": password,
        "note": note,
        "timestamp": timestamp,
    }


@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
@given(st.lists(entry_strategy(), min_size=1, max_size=10))
def test_storage_roundtrip(tmp_path, entries):
    vault_file = tmp_path / "vault.dat"
    master_pw = "pw1234"
    runner = CliRunner()
    # Initialize vault
    runner.invoke(
        cli, ["init", "--path", str(vault_file)], input=f"{master_pw}\n{master_pw}\n"
    )
    # Save entries directly
    save_entries(str(vault_file), master_pw, entries)
    # Load entries via CLI storage logic
    loaded = load_entries(str(vault_file), master_pw)
    assert loaded == entries
