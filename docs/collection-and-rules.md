# AD Monitor — Collection & Detection Rules Reference

AD Monitor implements 11 deterministic rule detectors alongside an Isolation Forest User Behavior Analysis (UBA) model. This document defines the exact Windows telemetry prerequisites, rule algorithms, and limitations for each.

## 1. Monitored Windows Event IDs

| Event ID | Provider | Channel | Description | Telemetry Extracted |
| --- | --- | --- | --- | --- |
| **4624** | `Microsoft-Windows-Security-Auditing` | `Security` | Successful Logon | Target SID, Account, WorkstationName, IpAddress, LogonType |
| **4625** | `Microsoft-Windows-Security-Auditing` | `Security` | Failed Logon | Target Account, FailureReason, WorkstationName, IpAddress |
| **4656** | `Microsoft-Windows-Security-Auditing` | `Security` | Handle Request to Object | Subject SID, ObjectName, AccessMask, Result (Denied / Success) |
| **4663** | `Microsoft-Windows-Security-Auditing` | `Security` | Attempted Access to Object | Subject SID, ObjectName, AccessMask (Read=0x1, Write=0x6, Delete=0x10000) |
| **4688** | `Microsoft-Windows-Security-Auditing` | `Security` | New Process Created | NewProcessName, CommandLine, ProcessId, ParentProcessId |
| **5145** | `Microsoft-Windows-Security-Auditing` | `Security` | Network Share Check | RelativeTargetName, ShareLocalPath, SubjectUserName, AccessMask |
| **1116** | `Microsoft-Windows-Windows Defender` | `Operational` | Threat Detected | Path, ThreatName, Severity |
| **4104** | `Microsoft-Windows-PowerShell` | `Operational` | Script Block Execution | ScriptBlockText, Path |

---

## 2. The 11 Detection Rules

### R1. Restricted Path Access Denied (`restricted`)
- **Required Telemetry:** `access_request` (Event 4656) or `share_check` (Event 5145) with `result = 'denied'`.
- **Target Paths:** `C:\ADMonitor-Demo\HR`, `C:\ADMonitor-Demo\Sensitive` (or UNC equivalent).
- **Threshold:** 1 access failure.
- **Alert Interpretation:** An employee attempted to open a file in a department folder for which their domain group has no permissions. Distinguishes genuine ACL denials from typos (`PathNotFound`).

### R2. Bulk Sensitive File Reads (`bulk`)
- **Required Telemetry:** `file_read` (Event 4663 with mask `0x1`).
- **Target Paths:** Scoped sensitive directories (`Sensitive`, `Finance`, `HR`).
- **Threshold:** Default 10 distinct files accessed within a 300-second window.
- **Algorithm:** Distinct canonical paths are counted per user within the sliding event-time window. Repeated reads to the same file increment the event count but not the distinct path count.

### R3. Canary Document Accessed (`canary`)
- **Required Telemetry:** `file_read` (Event 4663).
- **Target Path:** Exact decoy path `C:\ADMonitor-Demo\Sensitive\Canary-Payroll-Confidential.txt`.
- **Threshold:** 1 access event.
- **Alert Interpretation:** The decoy document has no operational purpose; any read indicates unauthorized folder browsing or targeted reconnaissance.

### R4. After-Hours Sensitive Activity (`after_hours`)
- **Required Telemetry:** `file_read` or `file_write` on sensitive paths.
- **Algorithm:** Event timestamp is converted to configured local timezone (`Asia/Kolkata`) and compared against business hours (`09:00 - 18:00`) and business days (Monday–Friday).
- **Testing Method:** Adjust backend policy hours rather than changing the DC system clock.

### R5. Data Staging and ZIP Creation (`staging`)
- **Required Telemetry:** `file_copy` events followed by `archive_create` (Event 4688 or instrumented archive operation).
- **Threshold:** 5 distinct file copies into a staging folder followed by archive creation within 300 seconds.

### R6. Removable Storage Copy Observed (`usb_copy`)
- **Required Telemetry:** Removable storage presence coupled with destination file transfer record.
- **Algorithm:** Requires destination drive to be classified as removable (`DriveType=2` or USB PnP) and verified byte count. Insertion alone is logged as a USB event, not a data theft alert.

### R7. Downloaded Script Execution Correlated (`download_execute`)
- **Required Telemetry:** `download` observation correlated with `script_block` (Event 4104) or `process_start` (Event 4688) at the identical canonical path within 300 seconds.

### R8. Measured Download Volume (`downloads`)
- **Required Telemetry:** `download` with measured byte count.
- **Threshold:** Default 10 MB in a 300-second window.

### R9. Rapid File Modifications (`rapid_change`)
- **Required Telemetry:** `file_write`, `file_rename`, `file_change`.
- **Target Paths:** Disposable scratch folder `C:\ADMonitor-Scratch`.
- **Threshold:** 15 distinct modifications within a 300-second window. Simulates anomalous mass-modification behavior harmlessly.

### R10. Non-Primary Device Access (`non_primary`)
- **Required Telemetry:** Access to sensitive paths from a workstation where the user does not have an established primary device association.

### R11. Windows Defender Detection (`antivirus`)
- **Required Telemetry:** Defender Event 1116 or 1117.
- **Severity:** High. Ingests threat detection metadata for correlation with user sessions.
