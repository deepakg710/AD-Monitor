import tempfile
from pathlib import Path
from backend.db import Database, now, stamp, js
from backend.rules import seed_rules, evaluate, readiness
from backend.ingestion import insert

def create_test_event(overrides=None):
    base = {
        "id": "ev_test_1",
        "identity": "ident_1",
        "time": now(),
        "received_at": now(),
        "event_id": 4656,
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_computer": "WIN-8IIRPFSV4GI.lab.local",
        "collector_id": "col_1",
        "source_record": "101",
        "user_sid": "S-1-5-21-1002",
        "account": "LAB\\sales.demo",
        "logon_id": "0x12345",
        "device_id": None,
        "access_device_id": None,
        "attribution": "Strong: same-server interactive logon session",
        "category": "access_request",
        "result": "denied",
        "object_path": "C:\\ADMonitor-Demo\\HR\\Demo-File-1.txt",
        "canonical_path": "c:\\admonitor-demo\\hr\\demo-file-1.txt",
        "source_address": "192.168.77.20",
        "process_id": "4",
        "process_guid": None,
        "parent_id": None,
        "process_path": None,
        "command_line": None,
        "fields": "{}",
        "raw": "<xml/>",
        "evidence_type": "windows_event_xml",
        "late_seconds": 0.5,
        "rules_done": 0
    }
    if overrides:
        base.update(overrides)
    return base

def test_rule_seeding_and_evaluation():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            # 18 rules seeded (15 original + 3 process/browser review rules)
            rules = c.execute("SELECT * FROM rules").fetchall()
            assert len(rules) == 18

            # Insert collector
            c.execute("INSERT INTO collectors(id, name, kind, token_hash, created_at) VALUES('col_1', 'DC Bridge', 'wef', 'hash', ?)", (now(),))

            # Test 1: Restricted path access denied
            e1 = create_test_event()
            insert(c, 'events', e1)
            evaluate(c, e1)

            # Check alert created
            alert = c.execute("SELECT * FROM alerts WHERE rule_id = 'restricted'").fetchone()
            assert alert is not None
            assert alert["severity"] == "Medium"
            assert alert["status"] == "Open"
            assert alert["account"] == "LAB\\sales.demo"

            # Test 2: Privilege attack
            e_priv = create_test_event({
                "id": "ev_priv_1",
                "identity": "ident_priv_1",
                "event_id": 4728,
                "category": "privilege_change",
                "object_path": "Domain Admins",
                "fields": js({"TargetUserName": "Domain Admins", "MemberName": "CN=sales.demo,CN=Users,DC=lab,DC=local"})
            })
            insert(c, 'events', e_priv)
            evaluate(c, e_priv)
            a_priv = c.execute("SELECT * FROM alerts WHERE rule_id = 'privilege_attack'").fetchone()
            assert a_priv is not None
            assert a_priv["severity"] == "High"

            # Test 3: Suspicious PowerShell execution
            e_ps = create_test_event({
                "id": "ev_ps_1",
                "identity": "ident_ps_1",
                "event_id": 4104,
                "category": "script_block",
                "command_line": "powershell.exe -enc dwBoAG8AYQBtAGkA"
            })
            insert(c, 'events', e_ps)
            evaluate(c, e_ps)
            a_ps = c.execute("SELECT * FROM alerts WHERE rule_id = 'suspicious_powershell'").fetchone()
            assert a_ps is not None
            assert a_ps["severity"] == "High"

def test_canary_rule():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            c.execute("INSERT INTO collectors(id, name, kind, token_hash, created_at) VALUES('col_1', 'DC Bridge', 'wef', 'hash', ?)", (now(),))

            # Configure canary path
            canary_path = "c:\\admonitor-demo\\sensitive\\canary.txt"
            cfg = {"threshold": 1, "window_seconds": 300, "cooldown_seconds": 600, "severity": "High", "paths": [canary_path], "employee_sids": [], "device_ids": []}
            c.execute("UPDATE rules SET config = ? WHERE id = 'canary'", (js(cfg),))

            e_canary = create_test_event({
                "id": "ev_canary_1",
                "identity": "ident_canary",
                "category": "file_read",
                "result": "success",
                "canonical_path": canary_path
            })
            insert(c, 'events', e_canary)
            evaluate(c, e_canary)

            alert = c.execute("SELECT * FROM alerts WHERE rule_id = 'canary'").fetchone()
            assert alert is not None
            assert alert["severity"] == "High"

def test_telemetry_readiness():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            rule = c.execute("SELECT * FROM rules WHERE id = 'restricted'").fetchone()
            # With empty events table, readiness should indicate missing telemetry
            status = readiness(c, rule)
            assert status["state"] == "Not ready"
            assert "access_request" in status["missing"]

def test_c2_beacon_threshold_and_aggregation():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            c.execute("INSERT INTO collectors(id, name, kind, token_hash, created_at) VALUES('col_1', 'Endpoint Agent', 'endpoint', 'hash', ?)", (now(),))

            # 1 single event should NOT trigger an alert when threshold is 5
            e_single = create_test_event({
                "id": "ev_c2_1",
                "identity": "ident_c2_1",
                "category": "network_connection",
                "fields": js({"c2_destination": "198.51.100.45:443", "interval_seconds": 3, "jitter_percent": 2.1})
            })
            insert(c, 'events', e_single)
            evaluate(c, e_single)

            alert = c.execute("SELECT * FROM alerts WHERE rule_id = 'c2_beacon'").fetchone()
            assert alert is None, "Single network connection should not trigger C2 beacon alert when threshold is 5"

            # Insert 4 more events in the same window (total 5)
            for i in range(2, 6):
                ev = create_test_event({
                    "id": f"ev_c2_{i}",
                    "identity": f"ident_c2_{i}",
                    "category": "network_connection",
                    "fields": js({"c2_destination": "198.51.100.45:443", "interval_seconds": 3, "jitter_percent": 2.1})
                })
                insert(c, 'events', ev)
                evaluate(c, ev)

            # Now alert must be triggered with observed=5, threshold=5, evidence_count=5
            alert = c.execute("SELECT * FROM alerts WHERE rule_id = 'c2_beacon'").fetchone()
            assert alert is not None
            exp = eval(alert["explanation"].replace("null", "None").replace("true", "True").replace("false", "False"))
            assert exp["observed"] == 5
            assert exp["threshold"] == 5
            assert exp["evidence_count"] == 5
            assert "Possible periodic outbound activity" in exp["detail"]

def test_failed_logon_wrong_password_counter():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            c.execute("INSERT INTO collectors(id, name, kind, token_hash, created_at) VALUES('col_1', 'DC Bridge', 'wef', 'hash', ?)", (now(),))

            # 1st wrong password attempt
            ev1 = create_test_event({
                "id": "ev_pw_1",
                "identity": "ident_pw_1",
                "event_id": 4625,
                "category": "sign_in",
                "result": "denied",
                "fields": js({"SubStatus": "0xC000006A", "WorkstationName": "LAB-PC01"})
            })
            insert(c, 'events', ev1)
            evaluate(c, ev1)

            alert = c.execute("SELECT * FROM alerts WHERE rule_id = 'failed_logon'").fetchone()
            assert alert is not None
            assert alert["title"] == "Failed sign-in / wrong password (1 attempt)"
            assert alert["severity"] == "Medium"

            # 2nd and 3rd wrong password attempts increment counter and escalate severity to High
            for i in (2, 3):
                ev = create_test_event({
                    "id": f"ev_pw_{i}",
                    "identity": f"ident_pw_{i}",
                    "event_id": 4625,
                    "category": "sign_in",
                    "result": "denied",
                    "fields": js({"SubStatus": "0xC000006A", "WorkstationName": "LAB-PC01"})
                })
                insert(c, 'events', ev)
                evaluate(c, ev)

            alert3 = c.execute("SELECT * FROM alerts WHERE rule_id = 'failed_logon'").fetchone()
            assert alert3["title"] == "Failed sign-in / wrong password (3 attempts)"
            assert alert3["severity"] == "High"
            exp = eval(alert3["explanation"].replace("null", "None").replace("true", "True").replace("false", "False"))
            assert exp["observed"] == 3
            assert exp["evidence_count"] == 3
            assert "wrong password entered" in exp["detail"]

