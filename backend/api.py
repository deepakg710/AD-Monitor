"""
Canonical compatibility entrypoint and CLI for AD Monitor.
Consolidates backend.api:app with backend.app:make_app so that start.ps1,
CLI commands, and automated tests all use the same application factory,
project-root database (data/admonitor.db), security boundaries, and API routes.
"""
from __future__ import annotations
import argparse
import json
import os
import secrets
import sys
from .app import make_app, ROOT
from .db import Database, audit, digest, now, uid
from .ingestion import find_device
from .security import create_user

_IS_CLI = __name__ == "__main__"
_IS_PYTEST = bool(os.environ.get("PYTEST_CURRENT_TEST") or "pytest" in sys.modules)
app = make_app(testing=_IS_PYTEST, start_worker=not (_IS_PYTEST or _IS_CLI))
db: Database = app.state.db


def _cli() -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.api", description="AD Monitor Administrative CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_admin = sub.add_parser("create-admin", help="Create or reset an administrator user")
    p_admin.add_argument("--username", required=True)
    p_admin.add_argument("--password", required=True)

    p_enroll = sub.add_parser("enroll-collector", help="Enroll or rotate a collector token")
    p_enroll.add_argument("--name", required=True)
    p_enroll.add_argument("--kind", required=True, choices=["endpoint", "browser", "bridge", "wef", "directory", "dc"])
    p_enroll.add_argument("--hostname", required=True)

    p_list = sub.add_parser("list-collectors", help="List enrolled collectors")

    p_rb = sub.add_parser("rollback-migration", help="Roll back SQLite migrations above target version")
    p_rb.add_argument("--target-version", default="2")

    args = parser.parse_args()

    if args.command == "create-admin":
        with db.tx() as c:
            ident = create_user(c, args.username.strip(), args.password, "Admin", "local-cli")
        print(json.dumps({"ok": True, "id": ident, "username": args.username.strip()}, indent=2))
        return 0

    if args.command == "enroll-collector":
        norm_kind = {"wef": "bridge", "dc": "directory"}.get(args.kind, args.kind)
        host = args.hostname.strip()
        if norm_kind in ("endpoint", "browser") and host.split(".")[0].upper() in (
            "DESKTOP-IACNTNH",
            "DESKTOP-IAUT7R9",
            "WIN-8IIRPFSV4GI",
        ):
            print("ERROR: Endpoint and browser monitoring are restricted to authorized employee VMs (e.g. LAB-PC01).", file=sys.stderr)
            return 1
        token = secrets.token_urlsafe(48)
        with db.tx() as c:
            did = None
            if norm_kind in ("endpoint", "browser"):
                did = find_device(c, host) or uid()
                c.execute("INSERT OR IGNORE INTO devices(id,hostname,inventory_at) VALUES(?,?,?)", (did, host, now()))
            existing = c.execute(
                "SELECT id FROM collectors WHERE kind=? AND name=? ORDER BY created_at DESC LIMIT 1",
                (norm_kind, args.name),
            ).fetchone()
            if existing:
                ident = existing["id"]
                c.execute(
                    "UPDATE collectors SET name=?, token_hash=?, enabled=1, device_id=COALESCE(?,device_id), expected_host=? WHERE id=?",
                    (args.name, digest(token), did, host, ident),
                )
                audit(c, "local-cli", "collector_rotate", {"id": ident, "kind": norm_kind, "hostname": host})
                action = "rotated"
            else:
                ident = uid()
                c.execute(
                    "INSERT INTO collectors(id,name,kind,token_hash,enabled,device_id,expected_host,created_at) VALUES(?,?,?,?,1,?,?,?)",
                    (ident, args.name, norm_kind, digest(token), did, host, now()),
                )
                audit(c, "local-cli", "collector_enroll", {"id": ident, "kind": norm_kind, "hostname": host})
                action = "enrolled"
        print(
            json.dumps(
                {
                    "status": action,
                    "collector_id": ident,
                    "name": args.name,
                    "kind": norm_kind,
                    "device_id": did,
                    "expected_host": host,
                    "token": token,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "list-collectors":
        with db.read() as c:
            rows = [
                dict(r)
                for r in c.execute(
                    "SELECT id, name, kind, enabled, device_id, expected_host, created_at, last_seen, accepted FROM collectors ORDER BY created_at"
                ).fetchall()
            ]
        print(json.dumps(rows, indent=2))
        return 0

    if args.command == "rollback-migration":
        tv = int(args.target_version) if str(args.target_version).isdigit() else args.target_version
        rolled = db.rollback_migration(tv)
        print(json.dumps({"rolled_back": rolled, "target_version": args.target_version}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
