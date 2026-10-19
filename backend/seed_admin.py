from pathlib import Path
from backend.db import Database
from backend.rules import seed_rules
from backend.security import HASHER

ROOT = Path(__file__).resolve().parent.parent

for db_rel in ["data/admonitor.db", "backend/data/admonitor.db"]:
    db_path = ROOT / db_rel
    db = Database(db_path)
    db.migrate()
    with db.tx() as c:
        seed_rules(c)
        for uid_val, uname, pwd in [
            ("admin_default_id", "admin", "admin12345"),
            ("deepak_id", "deepak", "AdminPassword123!"),
            ("deepak_admin_id", "deepak_admin", "AdminPassword123!"),
        ]:
            hashed = HASHER.hash(pwd)
            c.execute(
                """
                INSERT INTO users(id, username, password_hash, role, enabled, created_at)
                VALUES(?, ?, ?, 'Admin', 1, '2026-10-02T10:00:00Z')
                ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role='Admin', enabled=1
                """,
                (uid_val, uname, hashed),
            )
        c.execute("DELETE FROM login_attempts")
        users = [dict(r) for r in c.execute("SELECT username, role, enabled FROM users").fetchall()]
        print(f"Seeded {db_rel}: {users}")
