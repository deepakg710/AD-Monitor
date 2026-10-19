from __future__ import annotations
import secrets, time
from datetime import datetime, timezone, timedelta
from fastapi import Request, HTTPException, Depends, status
import argon2
from .db import now, dt, stamp, uid, digest, Database

hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    return hasher.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return hasher.verify(hashed, password)
    except Exception:
        return False

def check_login_throttle(c, identity: str) -> bool:
    row = c.execute("SELECT failures, until_time FROM login_attempts WHERE identity = ?", (identity,)).fetchone()
    if not row:
        return True
    if dt(row["until_time"]) > datetime.now(timezone.utc):
        return False
    # Throttling expired
    c.execute("DELETE FROM login_attempts WHERE identity = ?", (identity,))
    return True

def record_login_failure(c, identity: str):
    row = c.execute("SELECT failures FROM login_attempts WHERE identity = ?", (identity,)).fetchone()
    failures = (row["failures"] + 1) if row else 1
    # Exponential lock: 10s, 30s, 60s, 300s...
    lock_seconds = 5 * (2 ** min(failures - 1, 6))
    until_time = stamp(datetime.now(timezone.utc) + timedelta(seconds=lock_seconds))
    c.execute(
        "INSERT INTO login_attempts(identity, failures, until_time) VALUES(?, ?, ?) "
        "ON CONFLICT(identity) DO UPDATE SET failures = ?, until_time = ?",
        (identity, failures, until_time, failures, until_time)
    )

def clear_login_failure(c, identity: str):
    c.execute("DELETE FROM login_attempts WHERE identity = ?", (identity,))

def create_session(c, user_id: str, duration_hours: int = 12) -> tuple[str, str]:
    raw_token = secrets.token_hex(32)
    token_hash = digest(raw_token)
    csrf_token = secrets.token_hex(16)
    expires_at = stamp(datetime.now(timezone.utc) + timedelta(hours=duration_hours))
    c.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf, expires_at) VALUES(?, ?, ?, ?)",
        (token_hash, user_id, csrf_token, expires_at)
    )
    return raw_token, csrf_token

def resolve_user_from_token(c, token: str) -> dict | None:
    if not token:
        return None
    token_hash = digest(token)
    session = c.execute(
        "SELECT s.*, u.username, u.role, u.enabled FROM sessions s "
        "JOIN users u ON s.user_id = u.id WHERE s.token_hash = ?",
        (token_hash,)
    ).fetchone()
    if not session:
        return None
    if dt(session["expires_at"]) < datetime.now(timezone.utc):
        c.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    if not session["enabled"]:
        return None
    return {
        "id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
        "csrf": session["csrf"]
    }
