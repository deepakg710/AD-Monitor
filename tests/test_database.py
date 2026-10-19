import os, tempfile, sqlite3
from pathlib import Path
from backend.db import Database, now, stamp, dt, presence

def test_database_migration_and_wal():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        db = Database(db_path)
        db.migrate()

        with db.read() as c:
            # Verify WAL journal mode
            mode = c.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"

            # Verify tables exist
            tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            assert "users" in tables
            assert "events" in tables
            assert "alerts" in tables
            assert "devices" in tables
            assert "collectors" in tables
            assert "rules" in tables
            assert "features" in tables
            assert "models" in tables

def test_database_backup():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        backup_path = Path(td) / "backup.db"
        db = Database(db_path)
        db.migrate()

        with db.tx() as c:
            c.execute("INSERT INTO settings VALUES('test_key', '\"test_value\"')")

        db.backup(backup_path)
        assert backup_path.exists()

        b_conn = sqlite3.connect(backup_path)
        val = b_conn.execute("SELECT value FROM settings WHERE key='test_key'").fetchone()[0]
        b_conn.close()
        assert val == '"test_value"'

def test_presence_calculation():
    # Online <60s
    t_now = now()
    assert presence(t_now) == "Online"

    # Stale 60s - 180s
    from datetime import datetime, timezone, timedelta
    t_stale = stamp(datetime.now(timezone.utc) - timedelta(seconds=90))
    assert presence(t_stale) == "Stale"

    # Offline > 180s
    t_offline = stamp(datetime.now(timezone.utc) - timedelta(seconds=240))
    assert presence(t_offline) == "Offline"

    # Unknown
    assert presence(None) == "Unknown"
    assert presence("") == "Unknown"
