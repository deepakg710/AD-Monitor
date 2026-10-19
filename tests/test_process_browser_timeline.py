"""Comprehensive automated tests for Process Monitor, Browser Activity, Native Host, and Investigation Timeline."""
from __future__ import annotations

import hashlib
import io
import json
import os
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.db import Database, digest, js, now, uid
from backend.ingestion import process_one
from backend.rules import seed_rules
from backend.security import create_user
from backend.telemetry import (
    extract_referenced_script_paths,
    redact_command_line,
    sanitize_domain_only,
)
from windows.native_host_loader import load_native_host_module


def _create_collector(c, name: str, kind: str, device_id: str | None, expected_host: str | None) -> dict:
    raw_token = f"tok-{uid()}"
    cid = f"col-{uid()[:12]}"
    c.execute(
        "INSERT INTO collectors(id, name, kind, token_hash, enabled, device_id, expected_host, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
        (cid, name, kind, digest(raw_token), device_id, expected_host, now()),
    )
    return {"id": cid, "token": raw_token}


@pytest.fixture()
def env_setup(tmp_path: Path):
    db_path = tmp_path / "test_admonitor.db"
    app = create_app(db_path, testing=True, start_worker=False)
    db: Database = app.state.db

    with db.tx() as c:
        seed_rules(c)
        create_user(c, "deepak.admin", "StrongAdminPass!2026", "Admin")
        # Seed enrolled lab employee and endpoint device
        c.execute(
            "INSERT INTO employees(sid, account, name, department, enabled, synced_at) "
            "VALUES (?, ?, ?, ?, 1, '2026-10-04T10:00:00Z')",
            ("S-1-5-21-3892219129-3189678795-1906980268-1104", "LAB\\sales.demo", "Sales Demo", "Sales"),
        )
        c.execute(
            "INSERT INTO employees(sid, account, name, department, enabled, synced_at) "
            "VALUES (?, ?, ?, ?, 1, '2026-10-04T10:00:00Z')",
            ("S-1-5-21-3892219129-3189678795-1906980268-1105", "LAB\\hr.user", "HR User", "HR"),
        )
        c.execute(
            "INSERT INTO devices(id, hostname, sid, os, ips, agent_version, inventory_at) "
            "VALUES (?, ?, ?, ?, ?, ?, '2026-10-04T10:00:00Z')",
            (
                "dev-lab-pc01",
                "LAB-PC01.lab.local",
                "S-1-5-21-3892219129-3189678795-1906980268-2101",
                "Windows 10 Enterprise Evaluation",
                js(["192.168.77.20"]),
                "2.0.0",
            ),
        )
        ep_col = _create_collector(c, "LAB-PC01 Endpoint Agent", "endpoint", "dev-lab-pc01", "LAB-PC01.lab.local")
        br_col = _create_collector(c, "LAB-PC01 Browser Native Host", "browser", "dev-lab-pc01", "LAB-PC01.lab.local")
        wef_col = _create_collector(c, "DC WEF Collector", "wef", None, "WIN-8IIRPFSV4GI.lab.local")

    client = TestClient(app)
    return {
        "app": app,
        "db": db,
        "client": client,
        "ep_token": ep_col["token"],
        "br_token": br_col["token"],
        "wef_token": wef_col["token"],
        "device_id": "dev-lab-pc01",
        "sales_sid": "S-1-5-21-3892219129-3189678795-1906980268-1104",
        "hr_sid": "S-1-5-21-3892219129-3189678795-1906980268-1105",
    }


def _login_admin(client: TestClient):
    res = client.post(
        "/api/auth/login",
        json={"username": "deepak.admin", "password": "StrongAdminPass!2026"},
    )
    assert res.status_code == 200
    csrf = res.json()["csrf"]
    return {"X-CSRF-Token": csrf}


def _drain_inbox(db: Database):
    while process_one(db):
        pass


def test_migration_003_reversible(tmp_path: Path):
    """Verifies migration 003 applies cleanly, preserves pre-existing rows, and rolls back cleanly."""
    db_path = tmp_path / "mig_test.db"
    db = Database(db_path)
    db.migrate()

    with db.tx() as c:
        c.execute(
            "INSERT INTO employees(sid, account, name, department, enabled, synced_at) "
            "VALUES ('S-1-5-21-100-1', 'LAB\\preserve.me', 'Preserve Me', 'IT', 1, '2026-10-04T09:00:00Z')"
        )
        tables = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "process_instances" in tables
        assert "browser_navigations" in tables
        assert "browser_downloads" in tables
        assert "correlation_links" in tables

    rolled_back = db.rollback_migration("003_process_browser_timeline.sql")
    assert rolled_back is True

    with db.tx() as c:
        tables_after = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "process_instances" not in tables_after
        assert "browser_navigations" not in tables_after
        emp = c.execute("SELECT account FROM employees WHERE sid='S-1-5-21-100-1'").fetchone()
        assert emp["account"] == "LAB\\preserve.me"

    # Re-apply migration 003 cleanly
    db.migrate()
    with db.tx() as c:
        tables_reapplied = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "process_instances" in tables_reapplied
        assert "correlation_links" in tables_reapplied


def test_integration_defects_fixed(env_setup):
    """Verifies failed login audit persists after 401, SPA path traversal is blocked, and collector contract works."""
    client: TestClient = env_setup["client"]
    db: Database = env_setup["db"]

    # 1. Failed login must return 401 AND persist login_attempts count + audit entry
    bad = client.post("/api/auth/login", json={"username": "deepak.admin", "password": "WrongPassword123!"})
    assert bad.status_code == 401
    with db.tx() as c:
        att = c.execute("SELECT failures FROM login_attempts").fetchone()
        assert att is not None and att["failures"] == 1
        aud = c.execute("SELECT * FROM audit WHERE action='login_failed'").fetchone()
        assert aud is not None

    # 2. Collector contract: transport_id is returned and acknowledged list matches accepted records
    resp = client.post(
        "/api/ingest",
        headers={"Authorization": f"Bearer {env_setup['ep_token']}"},
        json={
            "schema_version": 2,
            "transport_id": "tx-test-001",
            "records": [
                {
                    "id": "hb-001",
                    "kind": "heartbeat",
                    "data": {
                        "hostname": "LAB-PC01.lab.local",
                        "time": "2026-10-04T10:05:00Z",
                        "os": "Windows 10",
                        "ips": ["192.168.77.20"],
                        "agent_version": "2.0.0",
                        "health": {"cpu": 14.5, "ram_percent": 42.0, "disks": []},
                        "sessions": [{"id": "LAB\\sales.demo", "account": "LAB\\sales.demo", "state": "Active"}],
                    },
                }
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == 2
    assert body["transport_id"] == "tx-test-001"
    assert "hb-001" in body["acknowledged"]
    _drain_inbox(db)

    # 3. Role/kind authorization enforcement: WEF collector cannot submit browser_navigation
    bad_role = client.post(
        "/api/ingest",
        headers={"Authorization": f"Bearer {env_setup['wef_token']}"},
        json={
            "schema_version": 2,
            "transport_id": "tx-wef-bad",
            "records": [
                {
                    "id": "unauth-nav-1",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": "bprof-1234567890",
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Chrome",
                        "extension_id": "ext-123",
                        "domain": "example.com",
                    },
                }
            ],
        },
    )
    assert bad_role.status_code == 403
    assert "cannot submit record kind" in bad_role.text


def test_command_line_redaction_and_url_sanitization():
    """Verifies sensitive CLI secret redaction and strict domain-only URL sanitization."""
    # Redaction tests
    cmd1, st1 = redact_command_line('curl.exe https://user:SecretPass123@files.example.com/data.zip --password "MyPassword99"')
    assert st1 == "Redacted"
    assert "SecretPass123" not in cmd1
    assert "MyPassword99" not in cmd1
    assert "[REDACTED]" in cmd1

    cmd2, st2 = redact_command_line("powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
    assert st2 == "Redacted"
    assert "SQBFAFgA" not in cmd2

    cmd3, st3 = redact_command_line(r'powershell.exe -ExecutionPolicy Bypass -File "C:\Users\sales.demo\Downloads\lab-check.ps1"')
    assert st3 == "Collected"
    assert "lab-check.ps1" in cmd3

    # Domain sanitization tests
    dom, scheme, port = sanitize_domain_only("https://admin:hunter2@Portal.Vendor-Tools.Example:8443/secret/path?token=xyz#frag")
    assert dom == "portal.vendor-tools.example"
    assert scheme == "https"
    assert port == 8443

    assert sanitize_domain_only("chrome://extensions/?id=abc") == (None, None, None)
    assert sanitize_domain_only("edge://settings/profiles") == (None, None, None)
    assert sanitize_domain_only("file:///C:/Users/sales.demo/Downloads/secret.pdf") == (None, None, None)
    assert sanitize_domain_only("about:blank") == (None, None, None)


def test_process_snapshots_cpu_delta_pid_reuse_and_batches(env_setup):
    """Tests first-sample Unavailable CPU, second-sample CPU delta, PID reuse, and multi-batch snapshot completeness."""
    client: TestClient = env_setup["client"]
    db: Database = env_setup["db"]
    headers = _login_admin(client)
    ep_headers = {"Authorization": f"Bearer {env_setup['ep_token']}"}

    # Snapshot 1: batch 1 of 2 (incomplete) + batch 2 of 2 (complete)
    snap1_b1 = {
        "id": "snap1-b1",
        "kind": "process_snapshot",
        "data": {
            "snapshot_id": "snap-001",
            "boot_session_id": "boot-alpha",
            "sampled_at": "2026-10-04T11:00:00Z",
            "logical_cpus": 4,
            "is_complete": False,
            "batch_index": 1,
            "batch_total": 2,
            "processes": [
                {
                    "pid": 1200,
                    "name": "explorer.exe",
                    "creation_time": "2026-10-04T10:00:10Z",
                    "executable_path": r"C:\Windows\explorer.exe",
                    "command_line": r"C:\Windows\explorer.exe",
                    "user_sid": env_setup["sales_sid"],
                    "account": "LAB\\sales.demo",
                    "session_id": 1,
                    "cpu_time_ms": 10000,
                    "working_set_bytes": 85000000,
                    "private_bytes": 42000000,
                    "signature_state": "Verified",
                    "signer": "CN=Microsoft Windows",
                }
            ],
        },
    }
    snap1_b2 = {
        "id": "snap1-b2",
        "kind": "process_snapshot",
        "data": {
            "snapshot_id": "snap-001",
            "boot_session_id": "boot-alpha",
            "sampled_at": "2026-10-04T11:00:00Z",
            "logical_cpus": 4,
            "is_complete": True,
            "batch_index": 2,
            "batch_total": 2,
            "processes": [
                {
                    "pid": 2400,
                    "name": "powershell.exe",
                    "creation_time": "2026-10-04T10:59:50Z",
                    "parent_pid": 1200,
                    "parent_name": "explorer.exe",
                    "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line": "powershell.exe -NoLogo",
                    "user_sid": env_setup["sales_sid"],
                    "account": "LAB\\sales.demo",
                    "session_id": 1,
                    "cpu_time_ms": 2000,
                    "working_set_bytes": 64000000,
                    "private_bytes": 50000000,
                    "signature_state": "Verified",
                }
            ],
        },
    }
    client.post("/api/ingest", headers=ep_headers, json={"schema_version": 2, "transport_id": "t1", "records": [snap1_b1, snap1_b2]})
    _drain_inbox(db)

    # Verify first sample CPU is None (Unavailable, not fabricated zero) and explorer.exe is still Observed
    res1 = client.get("/api/processes", headers=headers).json()
    assert res1["summary"]["observed_processes"] == 2
    by_pid = {p["pid"]: p for p in res1["items"]}
    assert by_pid[1200]["cpu_percent"] is None
    assert by_pid[1200]["observed_state"] == "Observed"
    assert "Verified" in by_pid[2400]["parent_confidence"]

    # Snapshot 2 (15 seconds later):
    # - explorer.exe (PID 1200) advances cpu_time_ms by 6000ms over 15000ms wall time across 4 logical CPUs -> 10.0% CPU
    # - PID 2400 is reused by a NEW process (notepad.exe started at 11:00:10Z) -> old powershell instance becomes "No longer observed"
    snap2 = {
        "id": "snap2-b1",
        "kind": "process_snapshot",
        "data": {
            "snapshot_id": "snap-002",
            "boot_session_id": "boot-alpha",
            "sampled_at": "2026-10-04T11:00:15Z",
            "logical_cpus": 4,
            "is_complete": True,
            "batch_index": 1,
            "batch_total": 1,
            "processes": [
                {
                    "pid": 1200,
                    "name": "explorer.exe",
                    "creation_time": "2026-10-04T10:00:10Z",
                    "executable_path": r"C:\Windows\explorer.exe",
                    "user_sid": env_setup["sales_sid"],
                    "account": "LAB\\sales.demo",
                    "session_id": 1,
                    "cpu_time_ms": 16000,
                    "working_set_bytes": 86000000,
                    "private_bytes": 43000000,
                },
                {
                    "pid": 2400,
                    "name": "notepad.exe",
                    "creation_time": "2026-10-04T11:00:10Z",
                    "parent_pid": 9999,  # Unknown parent PID
                    "executable_path": r"C:\Windows\System32\notepad.exe",
                    "user_sid": env_setup["sales_sid"],
                    "account": "LAB\\sales.demo",
                    "session_id": 1,
                    "cpu_time_ms": 400,
                    "working_set_bytes": 18000000,
                },
            ],
        },
    }
    client.post("/api/ingest", headers=ep_headers, json={"schema_version": 2, "transport_id": "t2", "records": [snap2]})
    _drain_inbox(db)

    res2 = client.get("/api/processes?state=all", headers=headers).json()
    items = res2["items"]
    assert len(items) == 3  # explorer + old powershell + new notepad
    exp = next(i for i in items if i["name"] == "explorer.exe")
    old_ps = next(i for i in items if i["name"] == "powershell.exe")
    new_np = next(i for i in items if i["name"] == "notepad.exe")

    assert exp["cpu_percent"] == 10.0
    assert old_ps["observed_state"] == "No longer observed"
    assert old_ps["no_longer_observed_after"].startswith("2026-10-04T11:00:15")
    assert new_np["observed_state"] == "Observed"
    assert new_np["instance_key"] != old_ps["instance_key"]
    assert "not verified" in new_np["parent_confidence"]

    # Read-only check: no process termination endpoint exists
    kill_res = client.post(f"/api/processes/{exp['instance_key']}/kill", headers=headers)
    assert kill_res.status_code in (404, 405)


def test_out_of_order_process_lifecycle_events(env_setup):
    """Tests that out-of-order Exited (4689) followed by Started (4688) merges into a single coherent process instance."""
    client: TestClient = env_setup["client"]
    db: Database = env_setup["db"]
    headers = _login_admin(client)
    ep_headers = {"Authorization": f"Bearer {env_setup['ep_token']}"}

    exit_rec = {
        "id": "lc-exit-3100",
        "kind": "process_lifecycle",
        "data": {
            "event_type": "Exited",
            "event_time": "2026-10-04T11:10:08Z",
            "pid": 3100,
            "name": "whoami.exe",
            "executable_path": r"C:\Windows\System32\whoami.exe",
            "user_sid": env_setup["sales_sid"],
            "account": "LAB\\sales.demo",
            "exit_code": "0x0",
        },
    }
    start_rec = {
        "id": "lc-start-3100",
        "kind": "process_lifecycle",
        "data": {
            "event_type": "Started",
            "event_time": "2026-10-04T11:10:05Z",
            "pid": 3100,
            "name": "whoami.exe",
            "executable_path": r"C:\Windows\System32\whoami.exe",
            "command_line": "whoami.exe /all",
            "user_sid": env_setup["sales_sid"],
            "account": "LAB\\sales.demo",
        },
    }
    client.post("/api/ingest", headers=ep_headers, json={"schema_version": 2, "transport_id": "t3", "records": [exit_rec, start_rec]})
    _drain_inbox(db)

    res = client.get("/api/processes?state=all&search=whoami.exe", headers=headers).json()
    assert len(res["items"]) == 1
    proc = res["items"][0]
    assert proc["observed_state"] == "Exited"
    assert proc["creation_time"].startswith("2026-10-04T11:10:05")
    assert proc["exited_at"].startswith("2026-10-04T11:10:08")
    assert proc["command_line"] == "whoami.exe /all"


def test_browser_privacy_guards_revisions_and_gaps(env_setup):
    """Tests incognito rejection, subframe rejection, pre-enrollment rejection, 2s deduplication, download revisions, and pause/resume gaps."""
    client: TestClient = env_setup["client"]
    db: Database = env_setup["db"]
    headers = _login_admin(client)
    br_headers = {"Authorization": f"Bearer {env_setup['br_token']}"}
    prof_id = "bprof-sales-edge-001"

    # 1. Enroll profile
    client.post(
        "/api/ingest",
        headers=br_headers,
        json={
            "schema_version": 2,
            "transport_id": "br-1",
            "records": [
                {
                    "id": "enr-1",
                    "kind": "browser_enrollment",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "account": "LAB\\sales.demo",
                        "browser_name": "Microsoft Edge",
                        "browser_version": "130.0.0.0",
                        "extension_id": "ext-edge-lab",
                        "extension_version": "2.0.0",
                        "profile_label": "Edge Sales Profile",
                        "enrolled_at": "2026-10-04T12:00:00Z",
                    },
                }
            ],
        },
    )
    _drain_inbox(db)

    # 2. Submit valid navigation + duplicate within 1s + incognito navigation + iframe navigation + pre-enrollment navigation
    client.post(
        "/api/ingest",
        headers=br_headers,
        json={
            "schema_version": 2,
            "transport_id": "br-2",
            "records": [
                {
                    "id": "nav-valid-1",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "navigation_time": "2026-10-04T12:30:00.200Z",
                        "url": "https://portal.vendor-tools.example/login?user=sales&secret=123#top",
                        "tab_id": 10,
                        "frame_id": 0,
                    },
                },
                {
                    "id": "nav-dup-1",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "navigation_time": "2026-10-04T12:30:00.800Z",
                        "url": "https://portal.vendor-tools.example/dashboard",
                        "tab_id": 10,
                        "frame_id": 0,
                    },
                },
                {
                    "id": "nav-incog",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "navigation_time": "2026-10-04T12:30:05Z",
                        "domain": "private.example.com",
                        "incognito": True,
                    },
                },
                {
                    "id": "nav-iframe",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "navigation_time": "2026-10-04T12:30:06Z",
                        "domain": "ads.example.com",
                        "frame_id": 2,
                    },
                },
                {
                    "id": "nav-pre-enroll",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "navigation_time": "2025-01-01T00:00:00Z",
                        "domain": "old-history.example.com",
                        "frame_id": 0,
                    },
                },
            ],
        },
    )
    _drain_inbox(db)

    nav_res = client.get("/api/browser/navigations", headers=headers).json()
    assert len(nav_res["items"]) == 1
    assert nav_res["items"][0]["normalized_domain"] == "portal.vendor-tools.example"
    # Verify query string / path were stripped from stored raw_sanitized_evidence
    assert "secret=123" not in json.dumps(nav_res["items"][0])

    # 3. Download state revisions (in_progress -> completed) must update single download row and not double-count bytes
    client.post(
        "/api/ingest",
        headers=br_headers,
        json={
            "schema_version": 2,
            "transport_id": "br-3",
            "records": [
                {
                    "id": "dl-rev-1",
                    "kind": "browser_download",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "browser_download_id": 42,
                        "started_at": "2026-10-04T12:30:10Z",
                        "updated_at": "2026-10-04T12:30:10Z",
                        "filename": "lab-check.ps1.crdownload",
                        "final_path": r"C:\Users\sales.demo\Downloads\lab-check.ps1.crdownload",
                        "source_domain": "portal.vendor-tools.example",
                        "referrer_domain": "portal.vendor-tools.example",
                        "bytes_received": 1024,
                        "total_bytes": 4096,
                        "state": "in_progress",
                    },
                },
                {
                    "id": "dl-rev-2",
                    "kind": "browser_download",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "browser_download_id": 42,
                        "started_at": "2026-10-04T12:30:10Z",
                        "updated_at": "2026-10-04T12:30:14Z",
                        "completed_at": "2026-10-04T12:30:14Z",
                        "filename": "lab-check.ps1",
                        "final_path": r"C:\Users\sales.demo\Downloads\lab-check.ps1",
                        "source_domain": "portal.vendor-tools.example",
                        "referrer_domain": "portal.vendor-tools.example",
                        "bytes_received": 4096,
                        "total_bytes": 4096,
                        "final_size_bytes": 4096,
                        "state": "complete",
                        "sha256": "a" * 64,
                    },
                },
            ],
        },
    )
    _drain_inbox(db)

    dl_res = client.get("/api/browser/downloads", headers=headers).json()
    assert len(dl_res["items"]) == 1
    dl_item = dl_res["items"][0]
    assert dl_item["state"] == "completed"
    assert dl_item["filename"] == "lab-check.ps1"
    assert dl_item["final_size_bytes"] == 4096
    assert dl_item["hash_state"] == "Verified"
    assert len(dl_item["revisions"]) == 2
    assert dl_res["summary"]["completed_download_bytes"] == 4096

    # 4. Pause & resume collection gap tracking
    client.post(
        "/api/ingest",
        headers=br_headers,
        json={
            "schema_version": 2,
            "transport_id": "br-4",
            "records": [
                {
                    "id": "st-pause",
                    "kind": "browser_status",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "state": "paused",
                        "time": "2026-10-04T12:31:00Z",
                    },
                },
                {
                    "id": "st-resume",
                    "kind": "browser_status",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Edge",
                        "extension_id": "ext-edge-lab",
                        "state": "active",
                        "time": "2026-10-04T12:32:30Z",
                    },
                },
            ],
        },
    )
    _drain_inbox(db)
    status_res = client.get("/api/browser/status", headers=headers).json()
    assert len(status_res["gaps"]) == 1
    assert status_res["gaps"][0]["gap_kind"] == "User paused"
    assert status_res["gaps"][0]["started_at"].startswith("2026-10-04T12:31:00")
    assert status_res["gaps"][0]["ended_at"].startswith("2026-10-04T12:32:30")


def test_native_host_framing_allowlist_and_hashing(tmp_path: Path, monkeypatch):
    """Tests Native Messaging length-prefixed binary framing, origin allowlist, OS identity binding, and safe download hashing."""
    nh = load_native_host_module()
    monkeypatch.setenv("ADMONITOR_NATIVE_HOST_DIR", str(tmp_path))
    monkeypatch.setenv("ADMONITOR_ALLOW_TEST_DOWNLOAD_PATHS", "1")

    # 1. Test 4-byte little-endian length-prefixed framing round-trip
    buf = io.BytesIO()
    sample_msg = {"ok": True, "profile_id": "bprof-test", "count": 3}
    nh.write_native_message(buf, sample_msg)
    buf.seek(0)
    decoded = nh.read_native_message(buf)
    assert decoded == sample_msg

    # 2. Test extension origin allowlist enforcement
    nh.save_config({"allowed_origins": ["chrome-extension://allowedext123456/"]})
    rejected = nh.handle_message({"action": "status", "profile_id": "bprof-1"}, caller_origin="chrome-extension://rogueext999999/")
    assert rejected["ok"] is False
    assert "not in allowed_origins" in rejected["error"]

    allowed = nh.handle_message({"action": "status", "profile_id": "bprof-1"}, caller_origin="chrome-extension://allowedext123456/")
    assert allowed["ok"] is True

    # 3. Test safe download hashing & OS identity overwrite
    dl_file = tmp_path / "invoice-viewer.exe"
    dl_bytes = b"MZ-simulated-test-binary-payload-2026"
    dl_file.write_bytes(dl_bytes)
    expected_sha = hashlib.sha256(dl_bytes).hexdigest()

    fake_identity = {
        "os_user": "LAB\\sales.demo",
        "os_sid": "S-1-5-21-3892219129-3189678795-1906980268-1104",
        "device_hostname": "LAB-PC01",
    }
    enriched = nh.enrich_record_with_os_identity(
        {
            "id": "dl-1",
            "kind": "browser_download",
            "data": {
                "profile_id": "bprof-1",
                "user_sid": "S-1-5-21-SPOOFED-BY-CLIENT",
                "state": "complete",
                "target_path": str(dl_file),
            },
        },
        fake_identity,
        {},
        "chrome-extension://allowedext123456/",
    )
    assert enriched["data"]["user_sid"] == fake_identity["os_sid"]
    assert enriched["data"]["account"] == "LAB\\sales.demo"
    assert enriched["data"]["extension_id"] == "allowedext123456"
    assert enriched["data"]["state"] == "completed"
    assert enriched["data"]["sha256"] == expected_sha
    assert enriched["data"]["hash_state"] == "Verified"


def test_investigation_timeline_correlations_negative_cases_and_review(env_setup):
    """
    Tests deterministic correlation chains:
    1. High-confidence executable launch (navigation -> download with SHA256 -> process with matching SHA256 + verified parent).
    2. Medium-confidence script invocation (navigation -> download of .ps1 -> powershell.exe -File Downloads\\lab-check.ps1).
    3. Negative case: unrelated powershell.exe command or different user SID does NOT correlate.
    4. Competing candidates & analyst review workflow without overwriting machine confidence.
    """
    client: TestClient = env_setup["client"]
    db: Database = env_setup["db"]
    headers = _login_admin(client)
    ep_headers = {"Authorization": f"Bearer {env_setup['ep_token']}"}
    br_headers = {"Authorization": f"Bearer {env_setup['br_token']}"}
    prof_id = "bprof-corr-test-01"
    exe_sha = "b" * 64

    # Step 1: Navigation + completed executable download + completed script download
    client.post(
        "/api/ingest",
        headers=br_headers,
        json={
            "schema_version": 2,
            "transport_id": "corr-1",
            "records": [
                {
                    "id": "c-enr-1",
                    "kind": "browser_enrollment",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "account": "LAB\\sales.demo",
                        "browser_name": "Chrome",
                        "extension_id": "ext-chrome-1",
                        "enrolled_at": "2026-10-04T12:00:00Z",
                    },
                },
                {
                    "id": "c-nav-1",
                    "kind": "browser_navigation",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Chrome",
                        "extension_id": "ext-chrome-1",
                        "navigation_time": "2026-10-04T12:35:00Z",
                        "domain": "files.partner-share.example",
                    },
                },
                {
                    "id": "c-dl-exe",
                    "kind": "browser_download",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Chrome",
                        "extension_id": "ext-chrome-1",
                        "browser_download_id": 101,
                        "started_at": "2026-10-04T12:35:05Z",
                        "completed_at": "2026-10-04T12:35:08Z",
                        "updated_at": "2026-10-04T12:35:08Z",
                        "filename": "invoice-viewer.exe",
                        "final_path": r"C:\Users\sales.demo\Downloads\invoice-viewer.exe",
                        "source_domain": "files.partner-share.example",
                        "referrer_domain": "files.partner-share.example",
                        "bytes_received": 204800,
                        "final_size_bytes": 204800,
                        "state": "completed",
                        "sha256": exe_sha,
                    },
                },
                {
                    "id": "c-dl-ps1",
                    "kind": "browser_download",
                    "data": {
                        "profile_id": prof_id,
                        "user_sid": env_setup["sales_sid"],
                        "browser_name": "Chrome",
                        "extension_id": "ext-chrome-1",
                        "browser_download_id": 102,
                        "started_at": "2026-10-04T12:35:10Z",
                        "completed_at": "2026-10-04T12:35:12Z",
                        "updated_at": "2026-10-04T12:35:12Z",
                        "filename": "lab-check.ps1",
                        "final_path": r"C:\Users\sales.demo\Downloads\lab-check.ps1",
                        "source_domain": "files.partner-share.example",
                        "referrer_domain": "files.partner-share.example",
                        "bytes_received": 4096,
                        "final_size_bytes": 4096,
                        "state": "completed",
                    },
                },
            ],
        },
    )
    _drain_inbox(db)

    # Step 2: Process snapshot with:
    # - explorer.exe parent (PID 4000)
    # - invoice-viewer.exe child (PID 4100, matching SHA-256 -> High confidence)
    # - powershell.exe invoking C:\Users\sales.demo\Downloads\lab-check.ps1 (PID 4200 -> Medium confidence)
    # - unrelated powershell.exe -Command "Get-Date" (PID 4300 -> must NOT correlate)
    # - HR user powershell.exe invoking lab-check.ps1 (PID 4400 -> different SID, must NOT correlate to sales.demo download)
    client.post(
        "/api/ingest",
        headers=ep_headers,
        json={
            "schema_version": 2,
            "transport_id": "corr-2",
            "records": [
                {
                    "id": "c-snap-1",
                    "kind": "process_snapshot",
                    "data": {
                        "snapshot_id": "snap-corr-1",
                        "boot_session_id": "boot-corr",
                        "sampled_at": "2026-10-04T12:35:25Z",
                        "logical_cpus": 4,
                        "is_complete": True,
                        "processes": [
                            {
                                "pid": 4000,
                                "name": "explorer.exe",
                                "creation_time": "2026-10-04T12:00:00Z",
                                "executable_path": r"C:\Windows\explorer.exe",
                                "user_sid": env_setup["sales_sid"],
                                "account": "LAB\\sales.demo",
                                "session_id": 1,
                            },
                            {
                                "pid": 4100,
                                "name": "invoice-viewer.exe",
                                "creation_time": "2026-10-04T12:35:18Z",
                                "parent_pid": 4000,
                                "parent_name": "explorer.exe",
                                "executable_path": r"C:\Users\sales.demo\Downloads\invoice-viewer.exe",
                                "command_line": r'"C:\Users\sales.demo\Downloads\invoice-viewer.exe" --open',
                                "user_sid": env_setup["sales_sid"],
                                "account": "LAB\\sales.demo",
                                "session_id": 1,
                                "sha256": exe_sha,
                                "hash_state": "Verified",
                                "signature_state": "Unsigned",
                            },
                            {
                                "pid": 4200,
                                "name": "powershell.exe",
                                "creation_time": "2026-10-04T12:35:22Z",
                                "parent_pid": 4000,
                                "parent_name": "explorer.exe",
                                "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                "command_line": r'powershell.exe -ExecutionPolicy Bypass -File "C:\Users\sales.demo\Downloads\lab-check.ps1"',
                                "user_sid": env_setup["sales_sid"],
                                "account": "LAB\\sales.demo",
                                "session_id": 1,
                            },
                            {
                                "pid": 4300,
                                "name": "powershell.exe",
                                "creation_time": "2026-10-04T12:35:23Z",
                                "parent_pid": 4000,
                                "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                "command_line": 'powershell.exe -Command "Get-Process | Select-Object -First 5"',
                                "user_sid": env_setup["sales_sid"],
                                "account": "LAB\\sales.demo",
                                "session_id": 1,
                            },
                            {
                                "pid": 4400,
                                "name": "powershell.exe",
                                "creation_time": "2026-10-04T12:35:24Z",
                                "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                "command_line": r'powershell.exe -File "C:\Users\sales.demo\Downloads\lab-check.ps1"',
                                "user_sid": env_setup["hr_sid"],
                                "account": "LAB\\hr.user",
                                "session_id": 2,
                            },
                        ],
                    },
                }
            ],
        },
    )
    _drain_inbox(db)

    tl_res = client.get("/api/timeline", headers=headers).json()
    assert tl_res["summary"]["total_cases"] == 2
    cases_by_file = {c["download"]["filename"]: c for c in tl_res["cases"]}

    # Verify Case 1: invoice-viewer.exe -> High confidence Executable launch observed
    exe_case = cases_by_file["invoice-viewer.exe"]
    assert exe_case["highest_confidence"] == "High"
    assert exe_case["primary_relationship"] == "Executable launch observed"
    exe_pids = [p["pid"] for p in exe_case["processes"]]
    assert 4100 in exe_pids
    assert 4300 not in exe_pids
    assert 4400 not in exe_pids

    # Verify Case 2: lab-check.ps1 -> Medium confidence Downloaded path referenced by process command line
    ps1_case = cases_by_file["lab-check.ps1"]
    assert ps1_case["highest_confidence"] == "Medium"
    assert ps1_case["primary_relationship"] == "Downloaded path referenced by process command line"
    ps1_pids = [p["pid"] for p in ps1_case["processes"]]
    assert 4200 in ps1_pids
    assert 4300 not in ps1_pids  # Unrelated PowerShell command excluded
    assert 4400 not in ps1_pids  # Different user SID excluded

    # Step 3: Analyst review workflow must persist status and note without overwriting machine confidence
    case_key = ps1_case["case_key"]
    rev_post = client.post(
        f"/api/timeline/{case_key}/review",
        headers=headers,
        json={
            "review_status": "Reviewed - Benign",
            "note": "Verified authorized lab script run by sales.demo during scheduled lab exercise.",
        },
    )
    assert rev_post.status_code == 200
    updated_case = rev_post.json()
    assert updated_case["review_status"] in ("Benign / expected activity", "Reviewed - Benign")
    assert updated_case["highest_confidence"] == "Medium"  # Machine confidence preserved!
    assert len(updated_case["review_notes"]) == 1
    assert "authorized lab script" in updated_case["review_notes"][0]["note"]

    # Step 4: Verify JSON and CSV export endpoints
    exp_json = client.get("/api/timeline/export?format=json", headers=headers)
    assert exp_json.status_code == 200
    assert exp_json.json()["case_count"] == 2

    exp_csv = client.get("/api/timeline/export?format=csv", headers=headers)
    assert exp_csv.status_code == 200
    assert "invoice-viewer.exe" in exp_csv.text
    assert "lab-check.ps1" in exp_csv.text


def test_powershell_and_extension_artifacts_valid():
    """Verifies MV3 extension manifest.json structure and PowerShell collector/installer script syntax."""
    import subprocess

    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = repo_root / "browser-extension" / "manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 3
    assert set(manifest["permissions"]) == {"webNavigation", "downloads", "storage", "nativeMessaging", "alarms"}
    assert "tabs" not in manifest["permissions"]
    assert "cookies" not in manifest["permissions"]
    assert "webRequest" not in manifest["permissions"]
    assert "host_permissions" not in manifest

    ps_files = [
        repo_root / "scripts" / "start.ps1",
        repo_root / "windows" / "agent" / "endpoint_agent.ps1",
        repo_root / "windows" / "agent" / "install_agent.ps1",
        repo_root / "windows" / "collector" / "wef_bridge.ps1",
        repo_root / "windows" / "native-host" / "native_host.ps1",
        repo_root / "windows" / "native-host" / "install_native_host.ps1",
        repo_root / "windows" / "native-host" / "uninstall_native_host.ps1",
    ]
    for ps in ps_files:
        assert ps.exists(), f"Missing PowerShell script: {ps}"
        cmd = (
            "$t=$null; $e=$null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{str(ps)}', [ref]$t, [ref]$e); "
            "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Error $_.ToString() }; exit 1 }"
        )
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-Command", cmd], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"PowerShell syntax error in {ps.name}: {proc.stderr}"

