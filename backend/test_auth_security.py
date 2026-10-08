import hashlib
import sqlite3
from pathlib import Path

import database


def test_frontend_pages_point_api_fetches_at_flask_port_5000():
    files = [
        Path("../frontend/login.html"),
        Path("../frontend/language.html"),
        Path("../frontend/chat.html"),
    ]
    for html_file in files:
        text = html_file.read_text(encoding="utf-8")
        assert "const SERVER_ORIGIN = 'http://127.0.0.1:5000';" in text
        assert "const API_BASE = SERVER_ORIGIN;" in text


def configure_test_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE", str(tmp_path / "security-test.db"))
    database.init_db()


def test_passwords_are_salted_and_slow_hashed(tmp_path, monkeypatch):
    configure_test_database(tmp_path, monkeypatch)
    database.register_user("Test User", "test@example.com", "SafePassword1!")

    conn = sqlite3.connect(database.DATABASE)
    stored_hash = conn.execute("SELECT password FROM users WHERE email = ?", ("test@example.com",)).fetchone()[0]
    conn.close()

    assert stored_hash.startswith("pbkdf2_sha256$")
    assert "SafePassword1!" not in stored_hash


def test_account_locks_after_five_failed_attempts(tmp_path, monkeypatch):
    configure_test_database(tmp_path, monkeypatch)
    database.register_user("Test User", "test@example.com", "SafePassword1!")

    for _ in range(4):
        assert database.login_user("test@example.com", "WrongPassword1")["success"] is False

    locked = database.login_user("test@example.com", "WrongPassword1")
    assert locked["success"] is False
    assert "temporarily locked" in locked["message"]

    still_locked = database.login_user("test@example.com", "SafePassword1!")
    assert still_locked["success"] is False
    assert "temporarily locked" in still_locked["message"]


def test_legacy_password_is_upgraded_after_a_successful_login(tmp_path, monkeypatch):
    configure_test_database(tmp_path, monkeypatch)
    legacy_hash = hashlib.sha256("SafePassword1!".encode("utf-8")).hexdigest()
    conn = sqlite3.connect(database.DATABASE)
    conn.execute(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        ("Legacy User", "legacy@example.com", legacy_hash),
    )
    conn.commit()
    conn.close()

    assert database.login_user("legacy@example.com", "SafePassword1!")["success"] is True
    conn = sqlite3.connect(database.DATABASE)
    upgraded_hash = conn.execute("SELECT password FROM users WHERE email = ?", ("legacy@example.com",)).fetchone()[0]
    conn.close()
    assert upgraded_hash.startswith("pbkdf2_sha256$")
