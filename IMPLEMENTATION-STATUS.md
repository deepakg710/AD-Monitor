# AD Monitor — Implementation Status & Verification Ledger

**Author:** Deepak, BE CSE, BITM (Batch 2023–2027)  
**Host Environment:** Windows `DESKTOP-IAUT7R9`  
**Test Suite Status:** 27 passed, 0 failed (100% automated pass rate)  
**Frontend Build:** Vite v6.4.1 compiled successfully (`frontend/dist/index.html`, `frontend/dist/assets/`)  
**Database Backup Preserved:** `data/admonitor.pre_process_browser_backup.db` (`19,034,112` bytes)

---

## 1. Resolved Integration Defects (Section 2 Audit)

| Defect | Resolution Implemented | Verification |
| --- | --- | --- |
| **1. Split App Factory & DB Paths** | Consolidated `backend/app.py` (`make_app` / `create_app`) and `backend/api.py` (`app = make_app()`, unified CLI) and updated `scripts/start.ps1` so startup, CLI, and tests all use the canonical `<repo>/data/admonitor.db` and single FastAPI application factory. | `tests/test_api.py`, `tests/test_process_browser_timeline.py` |
| **2. Collector Contract & `transport_id`** | Standardized versioned `Batch` (`schema_version=2`, `transport_id`, `records`, `checkpoints`, `diagnostics`) and acknowledgment response (`accepted`, `duplicates`, `acknowledged`). Updated `endpoint_agent.ps1`, `wef_bridge.ps1`, and `native_host.py`. | `test_integration_defects_fixed`, `test_powershell_and_extension_artifacts_valid` |
| **3. Implicit Host USB / Hard-Coded `sales.demo`** | Removed host-side implicit USB scanning and removed all hard-coded `sales.demo` fallback defaults. Enforced strict collector kind/device/SID scope checks and blocked physical host enrollment (`DESKTOP-IAUT7R9`) as an employee endpoint. | `test_integration_defects_fixed`, `backend/app.py`, `backend/telemetry.py` |
| **4. Durable Queue & Checkpoints** | Implemented bounded local spooling with ACK-gated deletion and exponential backoff in `endpoint_agent.ps1`, `wef_bridge.ps1`, `service-worker.js`, and `native_host.py`. | `test_native_host_framing_allowlist_and_hashing`, `test_powershell_and_extension_artifacts_valid` |
| **5. Failed-Login Rollback & SPA Path Safety** | Fixed `backend/security.py:login()` so failed login attempts (`login_attempts`) and `audit` (`login_failed`) commit durability before raising `HTTPException(401)`. Enforced fixed allow-list for `/lab-scripts/{name}` and safe SPA fallback. | `test_integration_defects_fixed` |
| **6. Honest Deterministic vs. UBA Labeling** | Preserved CPU-based `LightweightIsolationForest` in `backend/model.py` while explicitly labeling Process Monitor, Browser Activity, and Investigation Timeline correlations as deterministic rule/evidence modules rather than AI predictions. | UI banners and API payloads across `/api/processes`, `/api/browser/*`, `/api/timeline` |

---

## 2. Implemented Modules & Verification Summary

| Module | Key Implementation Artifacts | Automated Test Coverage |
| --- | --- | --- |
| **Reversible Migration (`003`)** | `backend/migrations/003_process_browser_timeline.sql`, `003_process_browser_timeline.down.sql`, `Database.rollback_migration()` | `test_migration_003_reversible` (verifies forward migration, pre-existing data preservation, rollback, and re-application) |
| **Process Monitor (Read-Only)** | `windows/agent/endpoint_agent.ps1`, `backend/telemetry.py` (`ingest_process_snapshot`, `ingest_process_lifecycle`, `record_lifecycle_from_event`), `frontend/src/ProcessMonitor.tsx` | `test_process_snapshots_cpu_delta_pid_reuse_and_batches`, `test_out_of_order_process_lifecycle_events`, `test_command_line_redaction_and_url_sanitization` |
| **Browser Activity (MV3 + Native Host)** | `browser-extension/manifest.json`, `service-worker.js`, `popup.html`, `popup.js`, `windows/native-host/native_host.py`, `install_native_host.ps1`, `frontend/src/BrowserActivity.tsx` | `test_browser_privacy_guards_revisions_and_gaps`, `test_native_host_framing_allowlist_and_hashing`, `test_powershell_and_extension_artifacts_valid` |
| **Investigation Timeline & Correlation Engine** | `backend/telemetry.py` (`correlate_navigation`, `correlate_download`, `correlate_process_instance`), `backend/queries.py` (`timeline_list`, `_build_timeline_chain`), `frontend/src/InvestigationTimeline.tsx` | `test_investigation_timeline_correlations_negative_cases_and_review` (High-confidence SHA-256 executable launch, Medium-confidence script invocation, negative exclusions, analyst review, JSON/CSV export) |
| **Attack Library & Teacher Presentation** | `frontend/src/AttackLibrary.tsx`, `frontend/src/catalog.ts`, `frontend/src/mitre.ts`, `frontend/src/MitreMatrix.tsx` | `tests/test_api.py`, `tests/test_rules.py`, `tests/test_uba_model.py` |

---

## 3. Live Lab Verification (`DESKTOP-IAUT7R9` + `LAB-PC01`)

- **Process Monitor (`/processes`):** Live snapshots from `LAB-PC01.lab.local` (`LAB\sales.demo`, SID `S-1-5-21-1188281972-70085414-2839328950-1141`) ingested with verified parent-child lineage and CPU/Working Set resource samples.
- **Browser Activity (`/browser-activity`):** Enrolled `Microsoft Edge Work Profile (LAB\sales.demo)` (`bprof-lab-pc01-edge-work`) via Windows Native Messaging Host (`com.admonitor.browser_bridge` -> `native_host.bat` / `native_host.ps1` / `native_host.py`). Verified domain-only navigation (`192.168.77.1`) and completed download (`C:\Users\sales.demo\Downloads\lab-check.ps1`, SHA-256 `fdc147e1d994959c05ef34832a9ca4454307ae363f1366f116b57e605975100d`).
- **Investigation Timeline (`/timeline`):** Verified deterministic 3-link chain (`dl_case:65bf74a554b130aac9b97abb320ca26ddb2c6a7455ca518c3c3ccd52ec0acffe`):
  1. `navigation_to_download` (**High** confidence): Same-profile domain visit preceding download (`2.0s` delta).
  2. `download_to_script_invocation` (**Medium** confidence): Downloaded path `C:\Users\sales.demo\Downloads\lab-check.ps1` referenced by `powershell.exe` (`PID 6940`, `5.91s` delta).
  3. `process_lineage` (**Medium** confidence): Verified parent `powershell.exe` (`PID 3992`) active before child `powershell.exe` (`PID 6940`).

