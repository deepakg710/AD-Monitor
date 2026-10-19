import tempfile
from pathlib import Path
from backend.db import Database, now, js, obj
from backend.ingestion import process_one
from backend.rules import seed_rules

def test_heartbeat_ingestion_and_health():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            seed_rules(c)
            # Create device and collector
            c.execute("INSERT INTO devices(id, hostname, inventory_at) VALUES('dev_pc01', 'LAB-PC01', ?)", (now(),))
            c.execute("INSERT INTO collectors(id, name, kind, token_hash, device_id, expected_host, created_at) "
                      "VALUES('col_agent', 'Agent LAB-PC01', 'endpoint', 'hash123', 'dev_pc01', 'LAB-PC01', ?)", (now(),))

            # Heartbeat payload
            hb_payload = {
                "kind": "heartbeat",
                "id": "hb_sample_1",
                "data": {
                    "hostname": "LAB-PC01",
                    "time": now(),
                    "os": "Windows 11 Pro",
                    "ips": ["192.168.77.20"],
                    "agent_version": "1.0.0",
                    "health": {
                        "cpu": 24.5,
                        "ram_percent": 62.0,
                        "ram_used": 4000000000,
                        "ram_available": 4000000000,
                        "ram_total": 8000000000,
                        "disks": [{"device_id": "C:", "percent": 48.0}]
                    },
                    "sessions": [{"id": "1", "account": "LAB\\sales.demo", "state": "Active"}],
                    "usb_events": [{"id": "usb_1", "time": now(), "action": "connected", "identifier": "USB\\VID_1234", "account": "LAB\\sales.demo", "metadata": {}}],
                    "errors": []
                }
            }

            c.execute("INSERT INTO inbox(collector_id, transport_id, payload, received_at) VALUES('col_agent', 'trans_1:0', ?, ?)",
                      (js(hb_payload), now()))

        # Process inbox
        assert process_one(db) is True

        with db.read() as c:
            # Verify device was updated
            dev = c.execute("SELECT * FROM devices WHERE id = 'dev_pc01'").fetchone()
            assert dev["os"] == "Windows 11 Pro"
            assert dev["last_heartbeat"] is not None

            # Verify health record created
            health = c.execute("SELECT * FROM health WHERE device_id = 'dev_pc01'").fetchone()
            assert health is not None
            assert health["cpu"] == 24.5
            assert health["ram_percent"] == 62.0

            # Verify session and USB records
            sess = c.execute("SELECT * FROM endpoint_sessions WHERE device_id = 'dev_pc01'").fetchone()
            assert sess["account"] == "LAB\\sales.demo"

            usb = c.execute("SELECT * FROM usb WHERE device_id = 'dev_pc01'").fetchone()
            assert usb["identifier"] == "USB\\VID_1234"
            assert usb["action"] == "connected"
