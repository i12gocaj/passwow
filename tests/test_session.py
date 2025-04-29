import time
from vault.session import load_session, save_session, clear_session

def test_save_and_load_session(tmp_path):
    key = b"secretkey"
    session_path = tmp_path / "sess.json"
    save_session(str(session_path), key)
    loaded = load_session(str(session_path), timeout=60)
    assert loaded == key

def test_session_expired(tmp_path, monkeypatch):
    key = b"secretkey"
    session_path = tmp_path / "sess.json"
    save_session(str(session_path), key)
    # Simulate time passage beyond the timeout
    original = time.time()
    monkeypatch.setattr(time, "time", lambda: original + 120)
    loaded = load_session(str(session_path), timeout=60)
    assert loaded is None

def test_clear_session(tmp_path):
    key = b"secretkey"
    session_path = tmp_path / "sess.json"
    save_session(str(session_path), key)
    assert session_path.exists()
    clear_session(str(session_path))
    assert not session_path.exists()
