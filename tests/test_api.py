import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.app import make_app
from backend.db import now

def test_full_api_workflow():
    with tempfile.TemporaryDirectory() as td:
        app = make_app(Path(td) / "test_api.db", testing=True, start_worker=False)
        client = TestClient(app)
        _run_workflow(client)

def _run_workflow(client: TestClient):
    # 0. Verify previously published default passwords are rejected
    for disallowed_pwd in ("admin12345", "AdminPassword123!", "password123456"):
        bad_setup = client.post("/api/auth/setup", json={"username": "deepak_admin", "password": disallowed_pwd})
        assert bad_setup.status_code == 422

    # 1. Setup first admin with a unique 12+ character passphrase
    unique_test_pass = "LabVerify_UniquePass#2026"
    resp = client.post("/api/auth/setup", json={"username": "deepak_admin", "password": unique_test_pass})
    assert resp.status_code == 200

    # 2. Login
    login_resp = client.post("/api/auth/login", json={"username": "deepak_admin", "password": unique_test_pass})
    assert login_resp.status_code == 200
    data = login_resp.json()
    token = data["token"]
    assert token is not None
    headers = {"Authorization": f"Bearer {token}"}

    # 3. /api/auth/me
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "deepak_admin"
    assert me_resp.json()["role"] == "Admin"

    # 4. /api/overview
    overview_resp = client.get("/api/overview", headers=headers)
    assert overview_resp.status_code == 200
    ov = overview_resp.json()
    assert "metrics" in ov
    assert "open_alerts" in ov["metrics"]
    assert "presence_counts" in ov["metrics"]

    # 5. /api/rules
    rules_resp = client.get("/api/rules", headers=headers)
    assert rules_resp.status_code == 200
    rules = rules_resp.json()
    assert len(rules) >= 11
    assert any(r["id"] == "restricted" for r in rules)

    # 6. Enroll collector
    enroll_resp = client.post("/api/collectors/enroll", json={"name": "Test Collector", "kind": "endpoint", "expected_host": "LAB-PC01"}, headers=headers)
    assert enroll_resp.status_code == 200
    collector_token = enroll_resp.json()["token"]
    assert collector_token is not None

    # 7. Ingest data using collector token
    ingest_body = {
        "transport_id": "test_batch_1",
        "records": [
            {
                "kind": "heartbeat",
                "id": "hb_api_1",
                "data": {
                    "hostname": "LAB-PC01",
                    "time": now(),
                    "os": "Windows 11",
                    "health": {"cpu": 15.0, "ram_percent": 45.0, "disks": []},
                    "sessions": [],
                    "usb_events": []
                }
            }
        ]
    }
    ingest_resp = client.post("/api/ingest", json=ingest_body, headers={"Authorization": f"Bearer {collector_token}"})
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] == 1

    # 8. Export events
    export_resp = client.get("/api/events/export?format=csv", headers=headers)
    assert export_resp.status_code == 200
    assert "time" in export_resp.text and "source_computer" in export_resp.text and "account" in export_resp.text

    # 9. Diagnostics
    diag_resp = client.get("/api/diagnostics", headers=headers)
    assert diag_resp.status_code == 200
    diag = diag_resp.json()
    assert "inbox_queue_depth" in diag
    assert "disk_free_mb" in diag

    # 10. Catalog summary for Attack Library & Teacher Presentation
    cat_resp = client.get("/api/catalog-summary", headers=headers)
    assert cat_resp.status_code == 200
    cat = cat_resp.json()
    assert "rules" in cat
    assert "open_by_rule" in cat
    assert len(cat["rules"]) >= 14
    c2_rule = next(r for r in cat["rules"] if r["id"] == "c2_beacon")
    assert c2_rule["name"] == "Possible periodic outbound activity"

