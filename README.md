# AD Monitor: AI-Driven Insider Threat Detection & Endpoint Monitoring using User Behavior Analytics (UBA)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.0+-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/deepakg710/AD-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/deepakg710/AD-Monitor/actions)
[![Status](https://img.shields.io/badge/Project-BE_CSE_Capstone_BITM-8A2BE2)](#author)

> **AD Monitor** is a defensive cybersecurity monitoring and investigation platform designed for Windows Active Directory lab environments. It combines Windows Security Event Forwarding (WEF), endpoint process telemetry, privacy-preserving browser activity monitoring, 19 deterministic detection rules, and CPU-based User Behavior Analytics (UBA) to help investigate potentially suspicious user and endpoint activity.
>
> Built as a Bachelor of Engineering (BE) in Computer Science and Engineering capstone project at **Ballari Institute of Technology & Management (BITM)**, AD Monitor demonstrates how multiple telemetry sources can be correlated into explainable, evidence-backed security investigations.
>
> **Project Scope**: Educational cybersecurity monitoring and controlled laboratory investigation. AD Monitor is designed for research, classroom demonstrations, and lab exercises—not as a commercial replacement for enterprise SIEM, EDR, or commercial incident response solutions.

---

## Table of Contents

- [Overview](#overview)
  - [Core Design Principles](#core-design-principles)
- [Key Features](#key-features)
  - [1. Windows Active Directory Monitoring](#1-windows-active-directory-monitoring)
  - [2. Read-Only Process Monitor (`/processes`)](#2-read-only-process-monitor---processes)
  - [3. Browser Activity (`/browser-activity`)](#3-browser-activity---browser-activity)
  - [4. Investigation Timeline (`/timeline`)](#4-investigation-timeline---timeline)
  - [5. Analyst Review and Case Export](#5-analyst-review-and-case-export)
  - [6. Attack Library and Teacher Presentation Mode](#6-attack-library-and-teacher-presentation-mode)
- [Detection and Analytics](#detection-and-analytics)
  - [Deterministic Detection Engine](#deterministic-detection-engine)
  - [User Behavior Analytics (UBA)](#user-behavior-analytics-uba)
- [System Architecture](#system-architecture)
  - [Backend Modules](#backend-modules)
- [Laboratory Topology](#laboratory-topology)
  - [Network Configuration](#network-configuration)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Installation and Deployment](#installation-and-deployment)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Collector Enrollment](#collector-enrollment)
  - [Browser Extension & Native Host Installation](#browser-extension--native-host-installation)
  - [Endpoint Agent Setup](#endpoint-agent-setup)
- [Testing and Verification](#testing-and-verification)
  - [Suggested Acceptance Criteria](#suggested-acceptance-criteria)
- [Security and Privacy](#security-and-privacy)
- [Known Limitations](#known-limitations)
- [Project Roadmap](#project-roadmap)
- [Author](#author)
- [Disclaimer](#disclaimer)

---

## Overview

Traditional log monitoring often inspects security events in isolation. However, investigating insider threats requires understanding the causal relationships between Active Directory logons, sensitive file access, browser downloads, process execution lineage, and changes in baseline user behavior.

AD Monitor addresses this challenge through a multi-source monitoring and evidence correlation workflow.

```
+---------------------------------------------------------------------------------------------------+
|                                   AD MONITOR INVESTIGATION ENGINE                                 |
+---------------------------------------------------------------------------------------------------+
|  [ WEF Windows Auditing ]   [ Endpoint Process Snapshots ]   [ Manifest V3 Browser Telemetry ]    |
|   - Event ID 4624/4625       - Sampled PID, SID, Command      - Top-Level Domain Navigations      |
|   - File Share ID 5145       - CPU Delta, Working Set         - Download Lifecycle Tracking       |
|   - Process ID 4688/4689     - Parent-Child Tree Lineage      - Sanitized Paths & SHA-256 Hashes  |
+------------------------------+--------------------------------+-----------------------------------+
                               |                                |
                               v                                v
+---------------------------------------------------------------------------------------------------+
|                            NORMALIZATION, ATTRIBUTION & INGESTION                                 |
|   - Durable SQLite Inbox Buffer (MSVCRT Lock)     - Reversible Migrations (001 -> 003)            |
|   - Windows Domain SID Attribution                - DPAPI-Protected Collector Tokens              |
+---------------------------------------------------------------------------------------------------+
                               |                                |
                               v                                v
+---------------------------------------------------------------+-----------------------------------+
|             19 DETERMINISTIC DETECTION RULES                  |    ISOLATION FOREST UBA ENGINE    |
|   - After-Hours Logon & Massive Staging                       |   - Pure-Python & NumPy Baseline  |
|   - Download-and-Execute Correlation                          |   - 7 Behavioral Feature Metrics  |
|   - Script Download & Suspicious PowerShell Execution         |   - Honest "Collecting Baseline"  |
+---------------------------------------------------------------+-----------------------------------+
                               |                                |
                               +----------------+---------------+
                                                |
                                                v
+---------------------------------------------------------------------------------------------------+
|                                    ANALYST USER INTERFACE                                         |
|  [ Security Overview ]  [ Process Monitor ]  [ Browser Activity ]  [ Timeline ]  [ Attack Library ]|
|  - Real-Time Metrics    - Read-Only Tree     - Privacy-Preserving  - Evidence    - Educational     |
|  - Active Threat Cases  - Verified Lineage   - Download Revisions  - Correlation - Teacher Present |
+---------------------------------------------------------------------------------------------------+
```

### Core Design Principles

1. **Evidence First**: Every alert is traceable directly to the underlying raw Windows event records, process creation telemetry, or browser download hashes.
2. **Explainability**: Findings describe what the activity was, which rule or baseline flagged it, and explicitly state what the evidence *does not* prove.
3. **Privacy by Design**: Browser collection is restricted to top-level domain names. Full URL paths, query strings, user credentials, cookies, private/incognito browsing, and form inputs are stripped before persistence.
4. **Read-Only Endpoint Monitoring**: The process monitor observes and correlates execution for forensic review. No remote kill-switches or invasive execution hooks exist.
5. **Honest Uncertainty**: Incomplete telemetry, missing audit policies, ambiguous timestamps, and UBA cold starts are communicated honestly (e.g., displaying `Collecting baseline` or `Unavailable` instead of zeroed or synthetic statistics).

---

## Key Features

### 1. Windows Active Directory Monitoring
AD Monitor ingests authentic Windows Security Auditing events forwarded via native Windows Event Forwarding (WEF):
- Centralized collection of forwarded Windows events (`4624`, `4625`, `4656`, `4663`, `4688`, `4689`, `5145`, `1116`, `4104`).
- Real-time event inspection, filtering, and JSON/CSV export.
- Reliable attribution to Windows user SIDs (`S-1-5-21-...`) and source workstation hostnames.
- Coordinated evaluation against deterministic Active Directory threat rules.

### 2. Read-Only Process Monitor — `/processes`
The lightweight endpoint agent collects process snapshots and supported process lifecycle events from enrolled Windows workstations:
- **Telemetry Collected**: Process ID (PID), stable instance key, process creation time, owner account and SID, session ID, cumulative CPU time, working set, private bytes, command line (with automatic sensitive token redaction), Authenticode signature verification status, and cached SHA-256 binary hash.
- **Process Lifecycle & Attribution**: Distinguishes observed process state from verified process termination. Missing processes in a snapshot are labeled `No longer observed` rather than assuming exit time unless an explicit Event `4689` / Sysmon `5` is received.
- **Lineage Verification**: Reconstructs parent-child process trees using validated instance relationships and creation timestamps rather than transient PIDs alone.
- **Honest CPU Deltas**: CPU % is computed from cumulative CPU-time delta over elapsed wall time. First observations display `Unavailable` because a delta has not yet elapsed.

### 3. Browser Activity — `/browser-activity`
The browser monitoring component uses a Chromium Manifest V3 extension paired with a Windows Native Messaging host:
- **Domain-Only Navigation**: Captures top-level (`frameId == 0`) `http`/`https` navigations, saving only the domain name. Path, query strings, fragments, passwords, page titles, and cookies are never persisted.
- **Download Monitoring**: Tracks download lifecycle transitions (`in_progress` &rarr; `completed` / `interrupted` / `canceled`) under a single logical download record to prevent double-counting.
- **Integrity Verification**: Computes bounded SHA-256 hashes of completed downloads inside approved user download folders.
- **Collection Transparency**: Displays explicit data-gap indicators (`User paused`, `Queue overflow drop`, `Native host disconnected`). Incognito/private windows are ignored by design.

### 4. Investigation Timeline — `/timeline`
Correlates disparate telemetry sources across an enrolled device and Windows user identity into a chronological investigation chain:
- **Multi-Sensor Correlation**: Links a domain visit &rarr; subsequent file download &rarr; process execution &rarr; spawned child processes.
- **Confidence Scoring**: Assigns `High`, `Medium`, or `Low` correlation confidence based on timestamp proximity, matched path, and user identity.
- **Evidence Boundaries**: Explicitly lists *What This Evidence Proves* and *What It Does Not Prove* (e.g., temporal proximity does not prove execution causality).

### 5. Analyst Review and Case Export
- Supported analyst dispositions: `Unreviewed`, `Needs follow-up`, `Benign / expected activity`, `Confirmed lab test`, `Escalate to alert`.
- Analysts can attach permanent review notes to any alert or timeline finding.
- Complete case export in formatted JSON or sanitized CSV.

### 6. Attack Library and Teacher Presentation Mode
- **17 Curated Educational Topics**: Covering credential dumping, DCSync, pass-the-hash, canary file access, after-hours exfiltration, C2 beaconing, and privilege escalation.
- **5-Tab Deep Dive**: `Explain`, `Evidence`, `Impact`, `Response`, and `References`.
- **4-Step Teacher Presentation Mode**: Tailored for classroom demonstrations, student seminars, and defense committee reviews.

---

## Detection and Analytics

### Deterministic Detection Engine

AD Monitor evaluates 19 deterministic rules across Active Directory, file access, endpoint behaviors, and browser activity:

| Rule Name | Severity | Purpose |
| :--- | :--- | :--- |
| `download_execute` | High | Correlates a browser file download with subsequent process execution by the same user. |
| `script_download_review` | High | Flags PowerShell, VBScript, or batch scripts downloaded from unapproved domains. |
| `downloads` | Medium | Detects anomalous download volume or sensitive extension downloads within a sliding window. |
| `domain_policy` | Medium | Flags navigation to unapproved external domains or known suspicious TLDs. |
| `sustained_resource` | Low | Evaluates prolonged high CPU or memory utilization by non-standard processes. |
| `restricted_access` | High | Monitors unauthorized access attempts to restricted Active Directory shares. |
| `bulk_sensitive_reads`| High | Flags rapid enumeration of sensitive documents or directories. |
| `canary_access` | Critical | Immediate detection when an operational honeytoken / canary file is opened. |
| `after_hours_access` | Medium | Identifies authenticated file activity outside configured business hours. |
| `staging_and_zip` | High | Detects rapid creation of archives (`.zip`, `.7z`) in staging folders (`C:\Temp`). |
| `usb_copy_simulation` | High | Monitors potential data movement toward removable USB storage devices. |
| `script_execution` | High | Flags encoded PowerShell (`-enc`, `-w hidden`) or non-standard scripting shells. |
| `rapid_file_mods` | High | Detects rapid file modification patterns indicative of ransomware or wiping. |
| `non_primary_device` | Medium | Identifies an employee logging into a machine that is not their assigned workstation. |
| `antivirus_detection` | High | Ingests Windows Defender alerts (`1116`) to link malware findings to user sessions. |
| *Additional Rules (4)* | Various | Account lockouts, privilege escalation attempts, password spraying, and persistence. |

### User Behavior Analytics (UBA)

AD Monitor features a pure-Python, CPU-friendly **Isolation Forest** model designed to spot behavioral anomalies without GPU overhead or third-party cloud APIs:
- **Baseline Requirements**: Requires at least 48 one-hour observation windows across a minimum of 7 days before issuing automated anomaly findings.
- **Cold-Start Transparency**: Explicitly reports `Collecting baseline` during initialization rather than generating false positive alerts on uncalibrated data.
- **Behavioral Features**: Evaluates 7 normalized metrics per user window (event volume, logon count, off-hours ratio, sensitive file touches, distinct workstations, failed authentications, process spawn rate).
- **Explainable Scores**: Each anomalous window outputs the specific contributing features and their deviations from the employee's historical distribution.

---

## System Architecture

```
+-----------------------------------------------------------------------------------------+
|                                    WINDOWS ACTIVE DIRECTORY LAB                         |
|                                                                                         |
|   +------------------------------------+   +-----------------------------------------+  |
|   |   Domain Controller (lab.local)    |   |     Workstation VM (LAB-PC01)           |  |
|   |  - Active Directory DS             |   |  - Manifest V3 Browser Extension        |  |
|   |  - Windows Event Forwarding (WEF)  |   |  - Native Messaging Host (Python/DPAPI) |  |
|   |  - SMB Sensitive File Shares       |   |  - Endpoint Agent (PowerShell)          |  |
|   +------------------+-----------------+   +--------------------+--------------------+  |
|                      |                                          |                       |
|                      | WEF / HTTP Ingest                        | Telemetry Batches     |
+----------------------|------------------------------------------|-----------------------+
                       |                                          |
                       +--------------------+---------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------------+
|                                AD MONITOR APPLICATION SERVER                            |
|                                                                                         |
|   FastAPI REST API (`backend/api.py`, `backend/app.py` on 127.0.0.1:8765)               |
|                                                                                         |
|   +--------------------------+   +-------------------------+   +--------------------+   |
|   | Ingestion Worker         |   | 19 Detection Rules      |   | Isolation Forest   |   |
|   | - MSVCRT File Lock       |   | - Cooldown Management   |   | - 7 Feature Metrics|   |
|   | - Durable SQLite Queue   |   | - Telemetry Readiness   |   | - Cold-Start Logic |   |
|   +------------+-------------+   +------------+------------+   +---------+----------+   |
|                |                              |                          |              |
|                +------------------------------+--------------------------+              |
|                                               |                                         |
|                                               v                                         |
|   +---------------------------------------------------------------------------------+   |
|   | SQLite Database in WAL Mode (`data/admonitor.db`)                               |   |
|   | - Reversible SQL Migrations (001_initial.sql -> 003_process_browser_timeline)   |   |
|   | - Argon2id Password Hashes, Session Management & CSRF Protection                |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
                                                |
                                                v
+-----------------------------------------------------------------------------------------+
|                                REACT 18 + TYPESCRIPT DASHBOARD                          |
|   - Recharts Visualizations    - Responsive Dark/Light UI    - Full REST API Client     |
|   - Read-Only Process Monitor  - Browser Privacy Monitor     - Investigation Timeline   |
+-----------------------------------------------------------------------------------------+
```

### Backend Modules

| Module | File | Responsibility |
| :--- | :--- | :--- |
| **App Factory** | [`backend/app.py`](backend/app.py) | Consolidated FastAPI factory (`make_app`), routing, middleware, and static asset serving. |
| **API Entry Point** | [`backend/api.py`](backend/api.py) | Canonical ASGI server entry point and command-line management interface. |
| **Database & Migrations**| [`backend/db.py`](backend/db.py) | Thread-safe SQLite connection pool, WAL mode, transaction context, and migrations. |
| **Telemetry Engine** | [`backend/telemetry.py`](backend/telemetry.py) | Process snapshot handling, browser sanitization, download lifecycle, and correlation. |
| **Ingestion Pipeline** | [`backend/ingestion.py`](backend/ingestion.py) | Collector authentication, inbox validation, single-instance background worker lock. |
| **Query Engine** | [`backend/queries.py`](backend/queries.py) | Parameterized queries for security overview, events, alerts, processes, and timelines. |
| **Detection Rules** | [`backend/rules.py`](backend/rules.py) | 19 deterministic threat rules, telemetry readiness checks, and cooldown timers. |
| **Schema Validation** | [`backend/schemas.py`](backend/schemas.py) | Pydantic v2 strict data models for ingestion, authentication, and analyst reviews. |
| **Security & Auth** | [`backend/security.py`](backend/security.py) | Argon2id password hashing, session tokens, CSRF validation, and brute-force lockouts. |
| **UBA Model** | [`backend/model.py`](backend/model.py) | Pure-Python/NumPy Isolation Forest implementation and behavioral feature extraction. |

---

## Laboratory Topology

The platform is designed to operate in a controlled, three-tier Active Directory lab environment:

| Role | Hostname / IP | Responsibility |
| :--- | :--- | :--- |
| **Application Host** | `DESKTOP-IAUT7R9`<br>`127.0.0.1` / `192.168.77.1` | Runs the FastAPI backend, SQLite database, and web UI. Never enrolled as a monitored endpoint. |
| **Domain Controller** | `WIN-8IIRPFSV4GI.lab.local`<br>`192.168.77.10` | Windows Server Active Directory (`lab.local`), DNS, WEF subscription manager, and canary SMB shares. |
| **Workstation VM** | `LAB-PC01.lab.local`<br>`192.168.77.20` | Enrolled endpoint VM (`LAB\sales.demo`). Runs endpoint agent, browser extension, and native host. |

### Network Configuration
- **Loopback**: Local access bound to `127.0.0.1:8765`.
- **Isolated Lab Network**: Workstation VMs communicate with the application host over a host-only virtual adapter (`192.168.77.0/24`).
- **Firewall Policy**: Port `8765` is accessible only from the isolated host-only subnet, preventing exposure to external networks.

---

## Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend Framework** | Python 3.11+, FastAPI, Uvicorn (ASGI) |
| **Data Validation** | Pydantic v2 (Strict Models) |
| **Database** | SQLite 3 with Write-Ahead Logging (WAL) |
| **Database Migrations** | Custom reversible SQL migrations (`001`, `002`, `003` + `.down.sql`) |
| **Machine Learning** | Pure-Python/NumPy Isolation Forest ($c(n)$ path length calculation) |
| **Frontend Framework** | React 18, TypeScript 5, Vite, Lucide React, Recharts |
| **Endpoint Collection** | Windows PowerShell 5.1 / 7 (Process snapshots + WMI/CIM) |
| **Event Transport** | Windows Event Forwarding (WEF) + WinRM / Windows Event Collector |
| **Browser Extension** | Chromium Manifest V3 (webNavigation, downloads, storage, alarms) |
| **Native Messaging Host** | Python 3 + Windows DPAPI credential encryption |
| **Authentication** | Argon2id (`argon2-cffi`), HTTP-only Lax session cookies, Bearer tokens, CSRF tokens |
| **Automated Testing** | `pytest`, `pytest-asyncio`, FastAPI `TestClient` |

---

## Repository Structure

```text
AD-Monitor/
├── README.md                           # Main project documentation
├── IMPLEMENTATION-STATUS.md            # Feature verification and milestone tracking
├── CHECKPOINT.md                       # Architecture notes and engineering log
├── requirements.txt                    # Python backend dependencies
├── pytest.ini                          # Automated test suite configuration
├── backend/
│   ├── app.py                          # FastAPI factory and static asset mount
│   ├── api.py                          # ASGI server entry point and CLI commands
│   ├── db.py                           # SQLite connection, WAL pragmas and migration runner
│   ├── telemetry.py                    # Process, browser and timeline correlation engine
│   ├── ingestion.py                    # Inbox queue, deduplication and background worker
│   ├── queries.py                      # Parameterized database query library
│   ├── rules.py                        # 19 deterministic threat detection rules
│   ├── schemas.py                      # Versioned Pydantic v2 contracts
│   ├── security.py                     # Argon2id hashing, sessions and CSRF
│   ├── model.py                        # Isolation Forest UBA model
│   ├── seed_admin.py                   # Administrative user bootstrap script
│   └── migrations/                     # Reversible SQL migrations (001, 002, 003)
├── frontend/
│   ├── src/                            # React 18 + TypeScript source code
│   │   ├── App.tsx                     # Navigation, authentication state and routing
│   │   ├── core.tsx                    # API client, theme context and reusable widgets
│   │   ├── Evidence.tsx                # Security Overview, Event Explorer & Event Detail
│   │   ├── ProcessMonitor.tsx          # Read-only process table, history and lineage tree
│   │   ├── BrowserActivity.tsx         # Domain navigation, download revisions & health
│   │   ├── InvestigationTimeline.tsx   # Multi-sensor correlation chains and evidence drawer
│   │   ├── AttackLibrary.tsx           # Educational attack catalog and Teacher Presentation
│   │   ├── Cases.tsx                   # Alert triage, investigation and note editor
│   │   ├── Inventory.tsx               # Enrolled devices, employees and USB history
│   │   └── Administration.tsx          # Rules editor, executive reports and diagnostics
│   └── dist/                           # Compiled production build served by FastAPI
├── browser-extension/
│   ├── manifest.json                   # Manifest V3 configuration
│   ├── service-worker.js               # Domain sanitizer, download tracker & batch queue
│   ├── popup/                          # Extension popup UI with pause/resume controls
│   └── icons/                          # Application extension icons
├── windows/
│   ├── agent/                          # endpoint_agent.ps1 & autostart scripts
│   ├── native-host/                    # native_host.py, manifest & registration scripts
│   ├── collector/                      # wef_bridge.ps1 for Domain Controller forwarding
│   ├── setup/                          # Lab setup, Active Directory sync & prerequisite checks
│   └── controlled-tests/               # 11 controlled, safe demonstration test scripts
├── tests/                              # Automated pytest suite (27 unit & integration tests)
├── scripts/                            # start.bat, start.ps1, stop.bat, install.bat, run_tests.bat
└── docs/                               # Detailed design & setup documentation
    ├── architecture.md                 # System architecture and data flow
    ├── windows-setup.md                # Windows AD, WEF and workstation configuration
    ├── collection-and-rules.md         # In-depth guide to 19 threat detection rules
    ├── teacher-demonstration.md        # Step-by-step classroom demo walkthrough
    └── limitations.md                  # Explicit engineering assumptions & boundaries
```

---

## Installation and Deployment

### Prerequisites
1. **Operating System**: Windows 10/11 or Windows Server 2019/2022.
2. **Python**: Python 3.11 or higher installed and added to `PATH`.
3. **PowerShell**: PowerShell 5.1 or PowerShell 7+ enabled.
4. **Browser**: Google Chrome or Microsoft Edge (for the browser extension).

### Quick Start

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/deepakg710/AD-Monitor.git
   cd AD-Monitor
   ```

2. **Run the installation script**:
   ```cmd
   scripts\install.bat
   ```
   *Creates a Python virtual environment, installs backend dependencies, and initializes the SQLite database.*

3. **Create your unique administrator account**:
   ```powershell
   .venv\Scripts\python -m backend.cli create-admin --username <your_admin_username>
   ```
   *Prompts privately via `getpass` for a unique 12+ character passphrase (hashed with Argon2id). No default or shared administrator credentials ship with AD Monitor, and previously published default passphrases are blocked at the authentication layer.*

4. **Start the application**:
   ```cmd
   scripts\start.bat
   ```
   *Launches the Uvicorn ASGI server on `http://127.0.0.1:8765`.*

5. **Sign in to the web dashboard**:
   - Open: **`http://localhost:8765`**
   - If no administrator account has been created yet via CLI, the web UI presents the **Initial Administrator Setup** screen requiring a unique 12+ character passphrase before first sign-in.

---

### Collector Enrollment

Generate one-time authentication tokens for your lab machines:

```powershell
# Enroll the endpoint process agent for LAB-PC01
python -m backend.api enroll-collector --name "LAB-PC01 Endpoint Agent" --kind endpoint --hostname LAB-PC01.lab.local

# Enroll the browser native messaging host for LAB-PC01
python -m backend.api enroll-collector --name "LAB-PC01 Browser Native Host" --kind browser --hostname LAB-PC01.lab.local
```

### Browser Extension & Native Host Installation

On the monitored employee workstation (`LAB-PC01`):
1. Open `chrome://extensions` or `edge://extensions` and enable **Developer Mode**.
2. Click **Load unpacked** and select the `browser-extension/` directory. Copy the assigned 32-character **Extension ID**.
3. Run the registration script in PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\windows\native-host\install_native_host.ps1 `
     -BackendUrl "http://192.168.77.1:8765" `
     -CollectorToken "<ONE_TIME_BROWSER_TOKEN>" `
     -ExtensionId "<32_CHARACTER_EXTENSION_ID>"
   ```

### Endpoint Agent Setup

On the monitored employee workstation (`LAB-PC01`):
```powershell
powershell -ExecutionPolicy Bypass -File .\windows\agent\install_agent.ps1 `
  -ServerUrl "http://192.168.77.1:8765" `
  -Token "<ONE_TIME_ENDPOINT_TOKEN>"
```

---

## Testing, Proof of Execution, and Sample I/O

Run the automated test suite:

```powershell
scripts\run_tests.bat
# or directly with pytest:
python -m pytest -v
```

### Verified Test Suite Output (`pytest -v`)

```text
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.1.1, pluggy-1.6.0
rootdir: AD-Monitor
configfile: pytest.ini
testpaths: tests
collecting ... collected 27 items

tests/test_api.py::test_full_api_workflow PASSED                         [  3%]
tests/test_database.py::test_database_migration_and_wal PASSED           [  7%]
tests/test_database.py::test_database_backup PASSED                      [ 11%]
tests/test_database.py::test_presence_calculation PASSED                 [ 14%]
tests/test_ingestion.py::test_heartbeat_ingestion_and_health PASSED      [ 18%]
tests/test_normalization.py::test_canonical_path PASSED                  [ 22%]
tests/test_normalization.py::test_scoped_paths PASSED                    [ 25%]
tests/test_normalization.py::test_parse_xml_4663_file_read PASSED        [ 29%]
tests/test_normalization.py::test_parse_xml_4656_access_denied PASSED    [ 33%]
tests/test_normalization.py::test_parse_defender_1116 PASSED             [ 37%]
tests/test_process_browser_timeline.py::test_migration_003_reversible PASSED [ 40%]
tests/test_process_browser_timeline.py::test_integration_defects_fixed PASSED [ 44%]
tests/test_process_browser_timeline.py::test_command_line_redaction_and_url_sanitization PASSED [ 48%]
tests/test_process_browser_timeline.py::test_process_snapshots_cpu_delta_pid_reuse_and_batches PASSED [ 51%]
tests/test_process_browser_timeline.py::test_out_of_order_process_lifecycle_events PASSED [ 55%]
tests/test_process_browser_timeline.py::test_browser_privacy_guards_revisions_and_gaps PASSED [ 59%]
tests/test_process_browser_timeline.py::test_native_host_framing_allowlist_and_hashing PASSED [ 62%]
tests/test_process_browser_timeline.py::test_investigation_timeline_correlations_negative_cases_and_review PASSED [ 66%]
tests/test_process_browser_timeline.py::test_powershell_and_extension_artifacts_valid PASSED [ 70%]
tests/test_rules.py::test_rule_seeding_and_evaluation PASSED             [ 74%]
tests/test_rules.py::test_canary_rule PASSED                             [ 77%]
tests/test_rules.py::test_telemetry_readiness PASSED                     [ 81%]
tests/test_rules.py::test_c2_beacon_threshold_and_aggregation PASSED     [ 85%]
tests/test_rules.py::test_failed_logon_wrong_password_counter PASSED     [ 88%]
tests/test_uba_model.py::test_isolation_forest_anomaly_detection PASSED  [ 92%]
tests/test_uba_model.py::test_cold_start_and_baseline PASSED             [ 96%]
tests/test_uba_model.py::test_explain_anomaly_format PASSED              [100%]

======================== 27 passed, 1 warning in 8.55s ========================
```

### Sample Telemetry Input & Correlated Timeline Output

**1. Sample Browser Navigation Input (`POST /api/ingest`)** — full URL submitted by collector:
```json
{
  "schema_version": 2,
  "transport_id": "br-2",
  "records": [
    {
      "id": "nav-valid-1",
      "kind": "browser_navigation",
      "data": {
        "profile_id": "bprof-sales-edge-001",
        "user_sid": "S-1-5-21-3842910112-1190445821-2910443110-1104",
        "browser_name": "Edge",
        "extension_id": "ext-edge-lab",
        "navigation_time": "2026-10-04T12:30:00.200Z",
        "url": "https://portal.vendor-tools.example/login?user=sales&secret=123#top",
        "tab_id": 10,
        "frame_id": 0
      }
    }
  ]
}
```

**2. Persisted Sanitized Output (`GET /api/browser/navigations`)** — query string, credentials, and path stripped before SQLite persistence:
```json
{
  "id": "nav-valid-1",
  "profile_id": "bprof-sales-edge-001",
  "normalized_domain": "portal.vendor-tools.example",
  "navigation_time": "2026-10-04T12:30:00.200Z",
  "browser_name": "Edge",
  "frame_id": 0
}
```

**3. Correlated Investigation Timeline Finding (`GET /api/timeline`)**:
```json
{
  "correlation_type": "download_to_process_execution",
  "confidence": "High",
  "user_sid": "S-1-5-21-3842910112-1190445821-2910443110-1104",
  "account": "LAB\\sales.demo",
  "hostname": "LAB-PC01",
  "what_it_proves": "Browser completed download of 'updater-helper.exe' from 'portal.vendor-tools.example' followed 12s later by process creation at the same canonical file path.",
  "what_it_does_not_prove": "Does not by itself prove malicious intent without binary inspection or command-line review."
}
```

---

## Security and Privacy

- **No Default Credentials**: AD Monitor ships with zero pre-seeded administrator accounts. Initial setup requires a unique 12+ character passphrase hashed with Argon2id (`time_cost=3, memory_cost=32768`), and known shared/default passphrases are rejected at both account creation and login.
- **Controlled Environment**: AD Monitor is built strictly for authorized laboratory environments. Never install monitoring collectors on personal devices or production networks without written consent.
- **Credential Protection**: Collector tokens are stored on endpoints using Windows Data Protection API (DPAPI) and sent via TLS/HTTPS headers.
- **Data Minimization**: Endpoint process command lines undergo regex token redaction before persistence. Browser history, search queries, passwords, and private tabs are rejected by design.
- **Separation of Concerns**: Machine correlation scores are kept strictly distinct from human analyst disposition notes and case conclusions.

---

## Known Limitations

- **Correlation is Not Causation**: Temporal proximity between a download and process execution strongly suggests, but does not definitively prove, that the downloaded file caused the process to launch.
- **Telemetry Blind Spots**: The platform relies on Windows Auditing policies (`Audit Process Creation`, `Audit File Share`). Misconfigured policies or disconnected collectors create blind spots.
- **Baseline Calibration**: Isolation Forest scores are relative to training data. Administrative batch jobs or system updates can appear anomalous if not represented in baseline periods.
- **Educational Scope**: AD Monitor is not engineered for high-availability enterprise clustering, kernel-level rootkit detection, or automated endpoint quarantine.

---

## Implemented & Verified vs. Planned Scope

| Capability | Status | Verification Method |
| :--- | :--- | :--- |
| Windows Event XML normalization (`4624`, `4625`, `4656`, `4663`, `4688`, `5145`, `1116`) | **Implemented & Verified** | `tests/test_normalization.py` (5 passed) |
| Read-only Process Monitor with CPU delta, PID reuse detection & lineage tree | **Implemented & Verified** | `tests/test_process_browser_timeline.py` |
| Manifest V3 domain-only Browser Extension + DPAPI Native Messaging Host | **Implemented & Verified** | `tests/test_process_browser_timeline.py` |
| Multi-sensor Investigation Timeline (`visit -> download -> execution -> child`) | **Implemented & Verified** | `tests/test_process_browser_timeline.py` |
| 19 Deterministic detection rules with cooldowns & telemetry readiness | **Implemented & Verified** | `tests/test_rules.py` (5 passed) |
| Pure-Python Isolation Forest UBA with 48-window cold-start gate | **Implemented & Verified** | `tests/test_uba_model.py` (3 passed) |
| Argon2id authentication, CSRF validation, and default-password blocklist | **Implemented & Verified** | `tests/test_api.py` |
| Microsoft Sysmon Network Connection (`Event ID 3`) ingestion | **Planned** | Roadmap |
| Automated Sigma rule YAML import/export translator | **Planned** | Roadmap |
| Cross-workstation lateral movement graph visualization | **Planned** | Roadmap |

---

## Author

**Deepak G.**  
Bachelor of Engineering — Computer Science and Engineering  
**Ballari Institute of Technology & Management (BITM)**, Ballari, Karnataka, India  
Academic Cycle: 2023–2027  
GitHub: [@deepakg710](https://github.com/deepakg710)

---

## Disclaimer

AD Monitor is developed exclusively for educational research, defensive security training, and authorized laboratory experimentation. It is not intended for covert surveillance, unauthorized monitoring, or unauthorized access to computer systems. All demonstration activities must be conducted inside isolated, explicitly authorized lab environments.
