"""
Interactive administrator bootstrap and credential rotation utility for AD Monitor.
Never seeds hardcoded or shared default credentials.
"""
from __future__ import annotations
import getpass
import os
import sys
from pathlib import Path
from backend.db import Database, audit, now, uid
from backend.rules import seed_rules
from backend.security import HASHER, validate_password_strength

ROOT = Path(__file__).resolve().parent.parent


def bootstrap_or_rotate_admin() -> int:
    username = os.environ.get("ADMONITOR_ADMIN_USER", "").strip()
    password = os.environ.get("ADMONITOR_ADMIN_PASSWORD", "")

    if not username:
        username = input("Administrator username (3-64 chars): ").strip()
    if not password:
        password = getpass.getpass("Unique administrator passphrase (12+ chars): ")
        confirm = getpass.getpass("Confirm administrator passphrase: ")
        if password != confirm:
            print("ERROR: Passphrases do not match.", file=sys.stderr)
            return 1

    try:
        validate_password_strength(username, password)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    db_Path = Path(os.environ.get("ADMONITOR_DB", str(ROOT / "data" / "admonitor.db")))
    db = Database(db_Path)
    db.migrate()
    hashed = HASHER.hash(password)
    with db.tx() as c:
        seed_rules(c)
        # Remove any legacy default bootstrap account IDs and invalidate existing sessions
        c.execute("DELETE FROM users WHERE id IN ('admin_default_id', 'deepak_id', 'deepak_admin_id') AND username != ?", (username,))
        c.execute("DELETE FROM sessions")
        c.execute("DELETE FROM login_attempts")
        c.execute(
            """
            INSERT INTO users(id, username, password_hash, role, enabled, created_at)
            VALUES(?, ?, ?, 'Admin', 1, ?)
            ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role='Admin', enabled=1
            """,
            (uid(), username, hashed, now()),
        )
        audit(c, "local-bootstrap", "admin_credentials_rotated", {"username": username})
    print(f"Configured administrator account '{username}' in {db_Path} and revoked prior sessions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(bootstrap_or_rotate_admin())
