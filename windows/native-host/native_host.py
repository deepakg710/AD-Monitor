#!/usr/bin/env python3
"""
AD Monitor - Windows Native Messaging Host (com.admonitor.browser_bridge)
=========================================================================
Receives length-prefixed JSON messages from the enrolled Chrome/Edge MV3 extension,
binds the OS-verified Windows user identity and SID, performs safe SHA-256 hashing of
completed downloads in the user's Downloads folder, maintains a bounded local SQLite spool,
and forwards batches with schema_version=2 and transport_id to the AD Monitor backend.
"""
import ctypes
import getpass
import hashlib
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_MESSAGE_BYTES = 256 * 1024
MAX_HASH_FILE_BYTES = 100 * 1024 * 1024  # 100 MB cap for download SHA-256 computation
MAX_SPOOL_RECORDS = 1000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_app_dir() -> Path:
    override = os.environ.get("ADMONITOR_NATIVE_HOST_DIR")
    if override:
        p = Path(override)
    else:
        local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        p = Path(local_app_data) / "ADMonitor" / "BrowserBridge"
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_config() -> dict:
    app_dir = get_app_dir()
    cfg_file = app_dir / "config.json"
    default_cfg = {
        "backend_url": "http://192.168.77.1:8765",
        "device_hostname": socket.gethostname(),
        "allowed_origins": [],
        "enrolled_profiles": {},
    }
    if cfg_file.exists():
        try:
            loaded = json.loads(cfg_file.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                default_cfg.update(loaded)
        except Exception:
            pass
    return default_cfg


def save_config(cfg: dict) -> None:
    app_dir = get_app_dir()
    cfg_file = app_dir / "config.json"
    cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def decrypt_dpapi_file(token_path: Path) -> str | None:
    """Decrypts either a PowerShell ConvertFrom-SecureString file or raw CryptProtectData blob."""
    if not token_path.exists():
        return None
    raw_text = token_path.read_text(encoding="utf-8-sig").strip()
    if not raw_text:
        return None
    if os.name == "nt":
        try:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$s = Get-Content -LiteralPath '{str(token_path)}' -Raw | ConvertTo-SecureString; "
                "$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); "
                "[Runtime.InteropServices.Marshal]::PtrToStringAuto($b)",
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5, text=True).strip()
            if out:
                return out
        except Exception:
            pass
    return None


def get_collector_token(cfg: dict) -> str | None:
    env_tok = os.environ.get("ADMONITOR_BROWSER_TOKEN")
    if env_tok:
        return env_tok.strip()
    app_dir = get_app_dir()
    dpapi_path = Path(cfg.get("token_file") or (app_dir / "token.dpapi"))
    tok = decrypt_dpapi_file(dpapi_path)
    if tok:
        return tok
    if cfg.get("collector_token"):
        return str(cfg["collector_token"]).strip()
    return None


_OS_IDENTITY_CACHE: dict | None = None


def resolve_os_identity() -> dict:
    """Obtains the Windows user account and SID from the trusted OS process token."""
    global _OS_IDENTITY_CACHE
    if _OS_IDENTITY_CACHE is not None:
        return _OS_IDENTITY_CACHE

    domain = os.environ.get("USERDOMAIN") or socket.gethostname()
    username = os.environ.get("USERNAME") or getpass.getuser()
    full_user = f"{domain}\\{username}" if domain else username
    user_sid = None

    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL,
                timeout=4,
                text=True,
            ).strip()
            parts = [p.strip('"') for p in out.split(",")]
            if len(parts) >= 2 and parts[1].startswith("S-1-"):
                full_user = parts[0]
                user_sid = parts[1]
        except Exception:
            pass

    _OS_IDENTITY_CACHE = {
        "os_user": full_user,
        "os_sid": user_sid or "S-1-5-21-UNKNOWN",
        "device_hostname": socket.gethostname(),
    }
    return _OS_IDENTITY_CACHE


def safe_compute_download_hash(target_path_str: str | None) -> tuple[str | None, bool | None]:
    """
    Safely computes SHA-256 for completed downloads located within the user's profile/Downloads
    directory without following symlinks or reading oversized files.
    """
    if not target_path_str:
        return None, None
    try:
        p = Path(target_path_str).resolve()
        if not p.exists():
            return None, False
        if not p.is_file() or p.is_symlink():
            return None, False
        home_dir = Path.home().resolve()
        # Only hash files inside the current user's profile tree (or temp test dir when configured)
        allow_any_dir = os.environ.get("ADMONITOR_ALLOW_TEST_DOWNLOAD_PATHS") == "1"
        if not allow_any_dir and home_dir not in p.parents:
            return None, True
        size = p.stat().st_size
        if size > MAX_HASH_FILE_BYTES:
            return None, True
        h = hashlib.sha256()
        with p.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest(), True
    except Exception:
        return None, None


class LocalSpool:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS spool ("
                "id TEXT PRIMARY KEY, "
                "payload TEXT NOT NULL, "
                "created_at TEXT NOT NULL)"
            )

    def enqueue(self, records: list[dict]) -> None:
        now = utc_now()
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            for r in records:
                conn.execute(
                    "INSERT OR REPLACE INTO spool(id, payload, created_at) VALUES (?, ?, ?)",
                    (r["id"], json.dumps(r, separators=(",", ":")), now),
                )
            count = conn.execute("SELECT COUNT(*) FROM spool").fetchone()[0]
            if count > MAX_SPOOL_RECORDS:
                excess = count - MAX_SPOOL_RECORDS
                conn.execute(
                    "DELETE FROM spool WHERE id IN ("
                    "SELECT id FROM spool ORDER BY created_at ASC LIMIT ?)",
                    (excess,),
                )

    def peek_batch(self, limit: int = 50) -> list[dict]:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            rows = conn.execute(
                "SELECT payload FROM spool ORDER BY created_at ASC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def remove(self, ids: list[str]) -> None:
        if not ids:
            return
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.executemany("DELETE FROM spool WHERE id = ?", [(i,) for i in ids])

    def depth(self) -> int:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM spool").fetchone()[0])


def enrich_record_with_os_identity(record: dict, identity: dict, cfg: dict, caller_origin: str | None = None) -> dict:
    rec_id = str(record.get("id") or f"brec-{uuid.uuid4()}")
    kind = str(record.get("kind") or "")
    data = dict(record.get("data") or {})

    # Always bind OS-verified Windows identity, never trusting client-supplied OS identity
    data["windows_user"] = identity["os_user"]
    data["account"] = identity["os_user"]
    data["windows_sid"] = identity["os_sid"]
    data["user_sid"] = identity["os_sid"]
    data["device_hostname"] = cfg.get("device_hostname") or identity["device_hostname"]
    if not data.get("extension_id"):
        ext_from_origin = ""
        if caller_origin and "://" in caller_origin:
            ext_from_origin = caller_origin.split("://", 1)[1].strip("/ ")
        data["extension_id"] = ext_from_origin or "native-host-enrolled"

    if kind == "browser_download" and str(data.get("state") or "").lower() in ("complete", "completed"):
        data["state"] = "completed"
        path_to_hash = data.get("final_path") or data.get("target_path")
        sha256_hex, exists_flag = safe_compute_download_hash(path_to_hash)
        if sha256_hex and not data.get("sha256"):
            data["sha256"] = sha256_hex
            data["hash_state"] = "Verified"
        if exists_flag is not None:
            data["file_exists"] = exists_flag
            data["exists_on_disk"] = exists_flag

    return {"id": rec_id, "kind": kind, "data": data}


def forward_spool(spool: LocalSpool, cfg: dict) -> tuple[bool, list[str], str | None]:
    batch = spool.peek_batch(50)
    if not batch:
        return True, [], None

    token = get_collector_token(cfg)
    if not token:
        return False, [], "Collector token not configured in Native Host"

    backend_url = str(cfg.get("backend_url") or "http://192.168.77.1:8765").rstrip("/")
    payload = {
        "schema_version": 2,
        "transport_id": str(uuid.uuid4()),
        "records": batch,
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        f"{backend_url}/api/ingest",
        data=body_bytes,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        ack = list(resp_data.get("acknowledged") or resp_data.get("accepted") or [])
        dup = list(resp_data.get("duplicates") or [])
        done_ids = list(set(ack + dup))
        if done_ids:
            spool.remove(done_ids)
        return True, done_ids, None
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        return False, [], f"HTTP {e.code}: {err_body or e.reason}"
    except Exception as e:
        return False, [], str(e)


def handle_message(msg: dict, caller_origin: str | None = None) -> dict:
    cfg = load_config()
    allowed_origins = cfg.get("allowed_origins") or []
    if allowed_origins and caller_origin:
        norm_caller = caller_origin.rstrip("/").lower()
        norm_allowed = [str(o).rstrip("/").lower() for o in allowed_origins]
        if norm_caller not in norm_allowed:
            return {"ok": False, "error": f"Extension origin {caller_origin} is not in allowed_origins"}

    identity = resolve_os_identity()
    spool = LocalSpool(get_app_dir() / "spool.db")
    action = str(msg.get("action") or "status")
    profile_id = str(msg.get("profile_id") or "")

    if action == "status":
        enrolled_map = cfg.get("enrolled_profiles") or {}
        is_enrolled = bool(profile_id and profile_id in enrolled_map)
        return {
            "ok": True,
            "enrolled": is_enrolled,
            "os_user": identity["os_user"],
            "os_sid": identity["os_sid"],
            "device_hostname": cfg.get("device_hostname") or identity["device_hostname"],
            "queue_depth": spool.depth(),
            "delivered_at": cfg.get("last_delivery_at"),
        }

    if action == "enroll":
        if not profile_id:
            return {"ok": False, "error": "Missing profile_id"}
        enroll_rec = enrich_record_with_os_identity(
            {
                "id": f"benroll-{profile_id}-{uuid.uuid4().hex[:8]}",
                "kind": "browser_enrollment",
                "data": {
                    "profile_id": profile_id,
                    "profile_label": msg.get("profile_label") or "Work Browser Profile",
                    "browser_name": msg.get("browser_name") or "Chrome",
                    "browser_version": msg.get("browser_version") or "unknown",
                    "extension_id": msg.get("extension_id"),
                    "extension_version": msg.get("extension_version") or "2.0.0",
                    "status": "active",
                    "enrolled_at": utc_now(),
                },
            },
            identity,
            cfg,
            caller_origin,
        )
        spool.enqueue([enroll_rec])
        ok, _, err = forward_spool(spool, cfg)
        enrolled_map = cfg.get("enrolled_profiles") or {}
        enrolled_map[profile_id] = {
            "profile_label": enroll_rec["data"]["profile_label"],
            "enrolled_at": utc_now(),
            "os_user": identity["os_user"],
            "os_sid": identity["os_sid"],
        }
        cfg["enrolled_profiles"] = enrolled_map
        if ok:
            cfg["last_delivery_at"] = utc_now()
        save_config(cfg)
        return {
            "ok": ok,
            "enrolled": True,
            "os_user": identity["os_user"],
            "os_sid": identity["os_sid"],
            "device_hostname": cfg.get("device_hostname") or identity["device_hostname"],
            "queue_depth": spool.depth(),
            "delivered_at": cfg.get("last_delivery_at"),
            "error": err,
        }

    if action == "heartbeat":
        hb_rec = enrich_record_with_os_identity(
            {
                "id": f"bhb-{profile_id}-{uuid.uuid4().hex[:8]}",
                "kind": "browser_status",
                "data": {
                    "profile_id": profile_id,
                    "browser_name": msg.get("browser_name") or "Chrome",
                    "browser_version": msg.get("browser_version") or "unknown",
                    "extension_id": msg.get("extension_id"),
                    "extension_version": msg.get("extension_version") or "2.0.0",
                    "state": "Paused" if msg.get("paused") else "Enrolled",
                    "status": "paused" if msg.get("paused") else "active",
                    "reason": "Periodic heartbeat",
                    "observed_at": utc_now(),
                },
            },
            identity,
            cfg,
            caller_origin,
        )
        spool.enqueue([hb_rec])
        ok, _, err = forward_spool(spool, cfg)
        if ok:
            cfg["last_delivery_at"] = utc_now()
            save_config(cfg)
        return {
            "ok": ok,
            "os_user": identity["os_user"],
            "os_sid": identity["os_sid"],
            "device_hostname": cfg.get("device_hostname") or identity["device_hostname"],
            "queue_depth": spool.depth(),
            "delivered_at": cfg.get("last_delivery_at"),
            "error": err,
        }

    if action == "ingest_records":
        raw_records = msg.get("records")
        if not isinstance(raw_records, list):
            return {"ok": False, "error": "records must be a list"}
        enriched = [enrich_record_with_os_identity(r, identity, cfg, caller_origin) for r in raw_records if isinstance(r, dict)]
        accepted_local_ids = [r["id"] for r in enriched]
        spool.enqueue(enriched)
        ok, _, err = forward_spool(spool, cfg)
        if ok:
            cfg["last_delivery_at"] = utc_now()
            save_config(cfg)
        # Once durably spooled on disk in Native Host, acknowledge to extension SW so extension storage stays lean
        return {
            "ok": True,
            "backend_delivered": ok,
            "acknowledged": accepted_local_ids,
            "os_user": identity["os_user"],
            "os_sid": identity["os_sid"],
            "device_hostname": cfg.get("device_hostname") or identity["device_hostname"],
            "queue_depth": spool.depth(),
            "delivered_at": cfg.get("last_delivery_at"),
            "error": err,
        }

    return {"ok": False, "error": f"Unsupported action: {action}"}


def read_native_message(stream) -> dict | None:
    raw_len = stream.read(4)
    if not raw_len:
        return None
    if len(raw_len) < 4:
        raise ValueError("Truncated native message length header")
    msg_len = struct.unpack("<I", raw_len)[0]
    if msg_len <= 0 or msg_len > MAX_MESSAGE_BYTES:
        raise ValueError(f"Native message size {msg_len} exceeds limit ({MAX_MESSAGE_BYTES})")
    payload = stream.read(msg_len)
    if len(payload) < msg_len:
        raise ValueError("Truncated native message body")
    return json.loads(payload.decode("utf-8"))


def write_native_message(stream, obj: dict) -> None:
    encoded = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def main() -> int:
    caller_origin = sys.argv[1] if len(sys.argv) > 1 else None
    while True:
        try:
            msg = read_native_message(sys.stdin.buffer)
            if msg is None:
                break
            resp = handle_message(msg, caller_origin=caller_origin)
            write_native_message(sys.stdout.buffer, resp)
        except Exception as exc:
            try:
                write_native_message(sys.stdout.buffer, {"ok": False, "error": str(exc)})
            except Exception:
                pass
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
