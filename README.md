# AD Monitor: AI-Driven Insider Threat Detection & Endpoint Monitoring using UBA

**AD Monitor** is a lightweight, full-stack cybersecurity monitoring and educational investigation workspace designed for Windows Active Directory lab environments. Built as a BE CSE college project (BITM, 2023–2027), it ingests genuine Windows Security Auditing events via Windows Event Forwarding (WEF), live read-only process telemetry and lifecycle events from enrolled employee VMs, privacy-first domain-level browser navigation & download metadata via a Manifest V3 extension + registered Windows Native Messaging host, evaluates 19 deterministic threat/correlation rules, trains a CPU-based Isolation Forest User Behavior Analysis (UBA) model, and provides an evidence-first **Investigation Timeline**, **Attack Library**, and **Teacher Presentation Mode**.

---

## Key Features

1. **Read-Only Process Monitor (`/processes`)**:
   - **Live Snapshot Sampling**: Endpoint agent (`windows/agent/endpoint_agent.ps1`) samples processes on enrolled employee VMs (e.g., `LAB-PC01`, default 15s interval) with boot/session ID, PID, creation time, stable `instance_key`, owner SID/account, session ID, working set, private bytes, command line (with sensitive secret redaction), Authenticode signature status, and cached SHA-256 hash.
   - **Honest CPU Delta & State Semantics**: Per-process CPU % is computed from cumulative CPU-time delta over elapsed wall time and logical CPU count (`Unavailable` on first observation rather than fabricated `0.0%`). Missing processes in a subsequent complete snapshot are labeled `No longer observed` with an observation interval unless a verified termination event (`4689` / Sysmon `5`) proves an exact exit time.
   - **Process Lifecycle & Verified Lineage**: Ingests Windows Security `4688`/`4689` and optional Sysmon `1`/`5` events, merges out-of-order start/exit records into coherent instances, and links parent-child processes only when creation-time order or `ProcessGuid` is verified (never PID alone). Strictly read-only — no remote process-kill endpoints or UI controls exist.

2. **Browser Activity — Manifest V3 Extension + Native Messaging Host (`/browser-activity`)**:
   - **Privacy-First Domain-Only Navigation**: Manifest V3 service worker (`browser-extension/`) captures top-level (`frameId == 0`) `http`/`https` navigations and strips full URLs, paths, query strings, fragments, credentials, page titles, form inputs, and cookies before persistence. Rejects incognito/private windows and pre-enrollment browser history imports.
   - **Registered Windows Native Host (`windows/native-host/native_host.py`)**: Uses 4-byte little-endian length-prefixed Native Messaging stdio framing, enforces `allowed_origins`, resolves the true Windows domain SID (`S-1-5-21-...`) from the OS process context (`whoami /user`), computes bounded SHA-256 hashes of completed downloads inside approved download directories, and spools batches durably with DPAPI-protected collector tokens.
   - **Download State Revisions & Collection Health**: Tracks download lifecycle transitions (`in_progress` → `completed` / `interrupted` / `canceled`) under a single logical download record without double-counting volume, and records explicit collection gaps (`User paused`, `Native host disconnected`, `Queue overflow drop`).

3. **Investigation Timeline — Deterministic Evidence Correlation (`/timeline`)**:
   - **Explainable Multi-Sensor Chains**: Links same-profile domain visits → browser file downloads → subsequent process creations and verified parent-child process lineage on the same enrolled device and Windows user SID.
   - **Explicit Confidence & Competing Candidates**: Assigns `High`, `Medium`, or `Low` confidence with explicit `matched_fields`, `missing_fields`, `competing_candidates`, *What This Evidence Proves*, and *What It Does Not Prove*.
   - **Analyst Review Workflow**: Supports analyst review decisions (`Unreviewed`, `Needs follow-up`, `Benign / expected activity`, `Confirmed lab test`, `Escalate to alert`) and persistent review notes without overwriting machine correlation confidence. Includes JSON and CSV case export.

4. **Attack Library, Impact Analysis & Teacher Presentation Mode (`/attack-library`, `/present`)**:
   - **17 Reviewed Educational Topics**: Searchable cards, plain-language glossary, comparison table, 5-tab detail view (`Explain`, `Evidence`, `Impact`, `Response`, `References`), and 4-step classroom Teacher Presentation mode.

5. **Dual Detection Engine (19 Deterministic Rules + UBA Isolation Forest)**:
   - **19 Configurable Rules**: Includes 14 core AD/file/endpoint rules plus 5 process/browser/correlation rules (`download_execute`, `script_download_review`, `downloads`, `domain_policy`, `sustained_resource`).
   - **CPU-Friendly UBA**: Lightweight Isolation Forest (`backend/model.py`) with honest cold-start handling (`Collecting baseline`).

---

## Directory Structure

```text
AD-Monitor/
  README.md
  IMPLEMENTATION-STATUS.md
  CHECKPOINT.md
  pytest.ini
  requirements.txt
  backend/
    app.py                  # Consolidated FastAPI application factory (make_app / create_app)
    api.py                  # Canonical ASGI entry point & CLI (create-admin, enroll-collector, rollback-migration)
    db.py                   # SQLite WAL database, reversible migrations & backup manager
    telemetry.py            # Process snapshots/lifecycle, browser sanitization/revisions & correlation engine
    ingestion.py            # Durable inbox worker, role/kind authorization, attribution & retention
    queries.py              # Parameterized SQLite queries for processes, browser, timeline, alerts & events
    rules.py                # 19 deterministic detection rules & telemetry readiness
    schemas.py              # Versioned Pydantic v2 ingestion & review contracts (schema_version=2)
    security.py             # Argon2id authentication, sessions, CSRF & login attempt auditing
    model.py                # UBA Isolation Forest model & baseline calculator
    migrations/             # 001_initial.sql, 002_jobs.sql, 003_process_browser_timeline.sql (+ .down.sql)
  frontend/
    src/
      ProcessMonitor.tsx        # Read-only Process Monitor (live table, history, lineage & detail drawer)
      BrowserActivity.tsx       # Browser Activity (domain visits, download revisions, profile health & gaps)
      InvestigationTimeline.tsx # Investigation Timeline (correlation chains, evidence drawer & analyst review)
      AttackLibrary.tsx         # Attack Library, Detail & Teacher Presentation views
      ...                       # Overview, Cases, Entities, Evidence, Administration
    dist/                   # Compiled static frontend bundle served by FastAPI
  browser-extension/
    manifest.json           # Manifest V3 extension (webNavigation, downloads, storage, nativeMessaging, alarms)
    service-worker.js       # Domain-only sanitizer, 2s deduplicator, download revision tracker & bounded queue
    popup.html / popup.js   # Transparency popup with pause/resume collection & flush controls
  windows/
    agent/                  # endpoint_agent.ps1 (heartbeat + process snapshots + 4688/4689/Sysmon 1/5 lifecycle)
    native-host/            # native_host.py, com.admonitor.browser_bridge.json, install/uninstall scripts
    collector/              # wef_bridge.ps1 for Domain Controller WEF forwarding
    setup/                  # setup_lab.ps1, ad_sync.ps1, prerequisites_check.ps1
    controlled-tests/       # Harmless controlled lab demonstration scripts
  tests/
    test_process_browser_timeline.py # End-to-end tests for migration 003, process, browser, native host & timeline
    ...                              # Full automated pytest suite (27 tests)
  scripts/                  # start.ps1, start.bat, install.bat, run_tests.bat
```

---

## Lab Topology & Deployment Guide

- **`DESKTOP-IAUT7R9` (Physical Host Laptop)**: Runs the FastAPI backend (`127.0.0.1` / `192.168.77.1:8765`), SQLite WAL database (`data/admonitor.db`), and React web UI. Never enrolled as a monitored employee endpoint.
- **`WIN-8IIRPFSV4GI.lab.local` (Domain Controller VM)**: Runs Active Directory (`lab.local`), SMB file shares (`C:\ADMonitor-Demo`), and `windows/collector/wef_bridge.ps1`.
- **`LAB-PC01` (Authorized Employee Workstation VM, `LAB\sales.demo`)**: Runs `windows/agent/endpoint_agent.ps1` and the enrolled browser profile (`browser-extension/` + `windows/native-host/install_native_host.ps1`).

### 1. Start Backend on `DESKTOP-IAUT7R9`
```powershell
.\scripts\start.ps1
```
Open `http://127.0.0.1:8765` in your browser.

### 2. Enroll Collectors on `DESKTOP-IAUT7R9`
```powershell
python -m backend.api enroll-collector --name "LAB-PC01 Endpoint Agent" --kind endpoint --hostname LAB-PC01.lab.local
python -m backend.api enroll-collector --name "LAB-PC01 Browser Native Host" --kind browser --hostname LAB-PC01.lab.local
```

### 3. Install Process Collector & Browser Native Host on `LAB-PC01`
On `LAB-PC01` (logged in as `LAB\sales.demo` or Administrator for agent setup):
1. Load `browser-extension/` as an unpacked extension in Chrome or Edge (`edge://extensions` or `chrome://extensions` with Developer Mode enabled) and copy the generated 32-character Extension ID.
2. Register the Native Messaging host for the current Windows user:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows\native-host\install_native_host.ps1 `
  -BackendUrl "http://192.168.77.1:8765" `
  -CollectorToken "<ONE_TIME_BROWSER_COLLECTOR_TOKEN>" `
  -ExtensionId "<32_CHAR_EXTENSION_ID>"
```
3. Run or install the Endpoint Agent with process snapshot & lifecycle collection enabled:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows\agent\install_agent.ps1 `
  -ServerUrl "http://192.168.77.1:8765" `
  -Token "<ONE_TIME_ENDPOINT_COLLECTOR_TOKEN>"
```

### 4. Run Automated Tests
```powershell
..\..\work\.venv\Scripts\python.exe -m pytest -v
```
