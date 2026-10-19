# AD Monitor: AI-Driven Insider Threat Detection & Endpoint Monitoring using User Behavior Analytics (UBA)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.0+-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows_AD_Lab-0078D6?logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
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

3. **Start the application**:
   ```cmd
   scripts\start.bat
   ```
   *Launches the Uvicorn ASGI server on `http://127.0.0.1:8765`.*

4. **Sign in to the web dashboard**:
   - Open: **`http://localhost:8765`**
   - Default Administrator Credentials:
     - **Username**: `admin`
     - **Password**: `admin12345`
     *(or use `deepak` / `AdminPassword123!`)*

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

## Testing and Verification

Run the comprehensive automated test suite:

```powershell
scripts\run_tests.bat
```
*or directly with pytest:*
```powershell
python -m pytest -v
```

### Test Coverage Highlights
- **`tests/test_database.py`**: SQLite WAL mode validation, table constraints, and schema migrations.
- **`tests/test_normalization.py`**: Accurate parsing of Windows Security XML (`4624`, `4688`, `5145`, Sysmon).
- **`tests/test_rules.py`**: Verification of all 19 detection rules with positive, negative, and cooldown cases.
- **`tests/test_uba_model.py`**: Verification of Isolation Forest math, baseline thresholding, and cold-start state.
- **`tests/test_process_browser_timeline.py`**: End-to-end multi-sensor correlation, Native Messaging framing, and download revision logic.
- **`tests/test_api.py`**: Complete REST API workflow, Argon2id authentication, and role authorization.

### Suggested Acceptance Criteria

| Component | Required Demonstration Evidence |
| :--- | :--- |
| **Windows Ingestion** | Genuine forwarded Event ID 4624/5145 appears in Event Explorer with preserved SID and timestamp. |
| **Process Monitoring** | Live process snapshot displays on `/processes` with accurate CPU delta and parent lineage tree. |
| **Browser Privacy** | Navigation table on `/browser-activity` shows top-level domain only; full URLs and queries are absent. |
| **Timeline Correlation** | Correlated chain appears on `/timeline` linking domain visit &rarr; download &rarr; process execution. |
| **Detection Engine** | Running `controlled-tests\03_canary_access.ps1` triggers an immediate Critical alert. |
| **UBA Cold-Start** | Dashboard displays `Collecting baseline` when feature windows are below the 48-window threshold. |
| **Security Controls** | Access without valid session or with invalid CSRF token returns `401 Unauthorized` / `403 Forbidden`. |

---

## Security and Privacy

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

## Project Roadmap

- [x] Windows Event Forwarding (WEF) ingestion pipeline
- [x] Read-only Process Monitor with verified parent-child lineage
- [x] Manifest V3 domain-level browser extension & Native Messaging host
- [x] Multi-source Investigation Timeline correlation engine
- [x] 19 Deterministic detection rules with telemetry readiness tracking
- [x] Pure-Python Isolation Forest UBA model with cold-start semantics
- [x] Attack Library with 17 scenarios and Teacher Presentation Mode
- [x] Executive case dossier export (PDF, JSON, CSV)
- [ ] Integration with Microsoft Sysmon Network Connection events (`Event ID 3`)
- [ ] Automated Sigma rule translation import/export utility
- [ ] Cross-workstation lateral movement graph visualization

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
