# Checkpoint

- **Host & Lab Preserved:** `DESKTOP-IAUT7R9` host, `WIN-8IIRPFSV4GI.lab.local` Domain Controller, `LAB-PC01` employee VM (`LAB\sales.demo`), and existing SQLite database (`data/admonitor.db`) preserved intact. Pre-migration backup saved at `data/admonitor.pre_process_browser_backup.db`.
- **Integration Defects Resolved:**
  - Consolidated `backend/app.py` and `backend/api.py` with unified `<repo>/data/admonitor.db`, `scripts/start.ps1`, and versioned collector contract (`schema_version=2`, `transport_id`, `acknowledged`).
  - Fixed failed-login transaction commit before `401`, removed implicit host USB scanning and hard-coded `sales.demo` defaults, and enforced collector role/kind authorization.
- **Process Monitor, Browser Activity & Investigation Timeline Implemented:**
  - Reversible migration `003_process_browser_timeline.sql` and `.down.sql` applied and tested.
  - Read-only Process Monitor (`/processes`) with live snapshots, CPU delta normalization (`Unavailable` on first sample), PID reuse handling, `4688`/`4689` + Sysmon `1`/`5` lifecycle merging, command-line secret redaction, and verified parent-child lineage.
  - Browser Activity (`/browser-activity`) with Manifest V3 extension (`browser-extension/`), Windows Native Messaging host (`windows/native-host/native_host.py`), OS-verified Windows SID binding, domain-only URL sanitization, download state revisions, and collection gap tracking.
  - Investigation Timeline (`/timeline`) with deterministic correlation chains (`High`/`Medium`/`Low` confidence, matched/missing fields, competing candidates), analyst review workflow, and JSON/CSV export.
- **Verification:**
  - Automated `pytest` suite passes **27 / 27** tests (including PowerShell AST parser validation and MV3 manifest checks); `npm.cmd run build` succeeds with 0 TypeScript errors.
  - **Live Windows Lab Verification (`DESKTOP-IAUT7R9` + `LAB-PC01`):** Verified live process snapshots (`170+` real process instances for `LAB\sales.demo` on `LAB-PC01`), enrolled Microsoft Edge profile (`bprof-lab-pc01-edge-work`), domain-only navigation (`192.168.77.1`), completed download (`C:\Users\sales.demo\Downloads\lab-check.ps1`, SHA-256 `fdc147e1d994959c05ef34832a9ca4454307ae363f1366f116b57e605975100d` Verified), and end-to-end Investigation Timeline correlation (`navigation_to_download` High confidence + `download_to_script_invocation` Medium confidence + `process_lineage` Medium confidence).
