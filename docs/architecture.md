# AD Monitor — System Architecture

**AD Monitor: AI-Driven Insider Threat Detection and Endpoint Monitoring using User Behavior Analysis (UBA)** is an evidence-based security monitoring application designed for Windows Active Directory environments.

## 1. High-Level Architecture

The system connects three tiers of components across physical and virtualized Windows machines:

```
[ Employee VM (LAB-PC01) ]                   [ DC VM (WIN-8IIRPFSV4GI) ]
  • User Activity (sales.demo)                  • Active Directory Services
  • Endpoint Agent (PowerShell)                 • Demo File Share (C:\ADMonitor-Demo)
      - CPU/RAM/Disk metrics                    • SACL Auditing (Read/Write/Delete)
      - User sessions (quser/WMI)               • WEF Collector (ForwardedEvents)
      - Removable storage (USB)                 • wef_bridge.ps1 Collector Bridge
      - 30s Heartbeats                          • ad_sync.ps1 AD Inventory Bridge
            │                                                 │
            │ (HTTP/HTTPS Bearer Auth)                        │ (HTTP/HTTPS Bearer Auth)
            ▼                                                 ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  AD Monitor Backend Host (DESKTOP-IAUT7R9 Physical Laptop) │
    │                                                             │
    │  1. Ingestion Endpoint (/api/ingest)                        │
    │     - Authenticated by per-collector bearer tokens          │
    │     - Idempotent queuing into transactional inbox table     │
    │                                                             │
    │  2. Background Worker Thread (msvcrt single-instance lock)  │
    │     - Normalizes Windows Event XML (parse_xml)              │
    │     - Canonicalizes paths (UNC share -> local disk path)    │
    │     - Performs client & logon session attribution           │
    │     - Evaluates 11 deterministic detection rules            │
    │     - Maintains UBA behavioral feature windows              │
    │     - Executes hourly data retention & evidence protection  │
    │                                                             │
    │  3. Database Tier (SQLite with WAL journal mode)            │
    │     - Fully parameterized schema with versioned migrations  │
    │     - Preserves original raw XML alongside normalized fields│
    │                                                             │
    │  4. User Behavior Analysis (UBA) Pipeline                   │
    │     - CPU-friendly Lightweight Isolation Forest             │
    │     - Per-user baseline calculation with cold-start guard   │
    │                                                             │
    │  5. REST API & Static Single Page Application (SPA)         │
    │     - FastAPI server with Argon2 authentication & CSRF      │
    │     - React 18 + TypeScript + Vite navy-themed interface   │
    └─────────────────────────────────────────────────────────────┘
```

## 2. Data Flow & Telemetry Paths

1. **Windows Security Events Flow**:
   - Monitored action occurs (e.g., file access on DC share).
   - Windows Security Auditing generates Event 4663/4656/5145.
   - Event is forwarded via Windows Event Forwarding (WEF) to DC `ForwardedEvents`.
   - `wef_bridge.ps1` reads records using a persistent XML bookmark, batches events, and POSTs them to `/api/ingest`.
   - Backend inbox stores raw payload; background worker parses XML, canonicalizes path, correlates employee identity, and triggers detection rules.

2. **Endpoint Health & Availability Flow**:
   - `endpoint_agent.ps1` runs inside employee VM (`LAB-PC01`).
   - Every 30 seconds, it samples CPU %, RAM %, disk utilization, interactive sessions, and USB drive attachments.
   - Payload is delivered to `/api/ingest`.
   - Backend evaluates device presence dynamically:
     - **Online**: Heartbeat received < 60 seconds ago.
     - **Stale**: Heartbeat received between 60 and 180 seconds ago.
     - **Offline**: Heartbeat received > 180 seconds ago.
     - **Unknown**: No usable heartbeat recorded.

3. **Active Directory Inventory Flow**:
   - `ad_sync.ps1` runs on DC `WIN-8IIRPFSV4GI`.
   - Extracts users, department groups, group memberships, and computer accounts.
   - Synchronizes inventory to backend, allowing association of accounts to departments (e.g., `LAB\sales.demo` -> `Sales-Users`).

## 3. Database Schema Overview

- `users`: Application analysts, administrators, and viewers with Argon2 password hashes.
- `sessions`: Session tokens with CSRF hashes and expiration.
- `collectors`: Registered collection bridges with unique authentication tokens.
- `devices`: Monitored machines with hardware specs, IP addresses, and presence history.
- `employees`: Active Directory user accounts, SIDs, and department assignments.
- `events`: Normalized security events with canonical paths, raw XML, and attribution.
- `inbox`: Idempotent staging table for incoming transport batches.
- `rules` & `rule_versions`: Version-controlled detection logic and thresholds.
- `alerts` & `alert_evidence`: Evidence-linked case files with status, disposition, and analyst notes.
- `features` & `models`: UBA temporal feature windows and persisted Isolation Forest model checkpoints.
