# AD Monitor — College Teacher Demonstration Guide

**Author:** Deepak, BE CSE, BITM (Batch 2023–2027)  
**Project:** AD Monitor: AI-Driven Insider Threat Detection & Endpoint Monitoring using User Behavior Analysis (UBA)

---

## 1. Executive Summary for Evaluators

When presenting AD Monitor to teachers and external project evaluators, emphasize these three core differentiators:

1. **Real Evidence, Not a Simulation:**  
   Every chart, alert, and metric displayed in AD Monitor is driven by persisted SQLite database records ingested from authorized Windows virtual machines. There are no randomized timers, fake alerts, or artificial mock statistics.
2. **Dual-Engine Security Analysis:**  
   Combines deterministic, explainable security rules (e.g., restricted directory ACL violations, canary accesses) with a genuine machine learning pipeline (**Lightweight Isolation Forest** running efficiently on CPU) for behavioral anomaly detection.
3. **Full Working Stack:**  
   Complete end-to-end implementation featuring a modern React/TypeScript dashboard, FastAPI backend with WAL-mode SQLite, background event worker, durable WEF event collection, and Windows endpoint agents.

---

## 2. Step-by-Step Demonstration Walkthrough

### Part 1: Architecture & Honest Empty State (2 Minutes)
1. **Open the Dashboard:** Navigate to `http://localhost:8000` and log in with your administrative account.
2. **Point out Honest Empty States:**
   - Point out that before events are generated, metrics read **0** events, **0** alerts, and **Unknown** presence for devices without heartbeats.
   - Explain to the evaluators: *"Unlike superficial web project demos that seed fake alerts with `Math.random()`, AD Monitor reflects the true operational state of the lab."*

### Part 2: Monitored Workstation Telemetry (3 Minutes)
1. On `LAB-PC01` (Windows 11 VM), start the endpoint agent:
   ```powershell
   cd C:\ADMonitor\agent
   .\endpoint_agent.ps1 -BackendUrl "http://192.168.77.1:8000" -AgentToken "<YOUR_TOKEN>"
   ```
2. In the Web Dashboard:
   - Navigate to **Devices**. Show that `LAB-PC01` shifts dynamically to **Online** within 60 seconds.
   - Open `LAB-PC01` details: Show real CPU percentage, physical RAM usage, disk space partitions, and active logon session (`LAB\sales.demo`).
   - Plug in or simulate a USB drive to show the live hardware event logged under **USB History**.

### Part 3: The Core Threat Scenario: Sales vs. HR Access (4 Minutes)
1. Explain the lab scenario: *"Our domain user `LAB\sales.demo` belongs to `Sales-Users` and is authorized to view Sales documents, but restricted from accessing HR records."*
2. On `LAB-PC01`, execute the controlled test:
   ```powershell
   cd C:\ADMonitor\controlled-tests
   .\01_normal_and_restricted_access.ps1
   ```
3. Observe the outputs:
   - Reading `Sales\Demo-File-1.txt` succeeds.
   - Reading `HR\Demo-File-1.txt` triggers an operating system **Access Denied** exception.
4. Switch to the AD Monitor Dashboard:
   - In **Event Explorer**, filter by `sales.demo`. Show the two distinct events:
     - Event 1: `file_read` &rarr; `result: success` on the Sales file.
     - Event 2: `access_request` &rarr; `result: denied` on the HR file.
   - Click **Inspect** on the denied event to show evaluators the actual **raw Windows Event XML** containing the Windows Security Event ID 4656/4663 record with the user SID and object path.
5. In **Alerts**, show that a new **Medium Severity Alert** was automatically created:
   - Title: *Restricted path access denied*.
   - Attribution: *Strong: same-server interactive logon session*.

### Part 4: Case Investigation & Dispositioning (3 Minutes)
1. Click **Investigate** on the generated alert.
2. Review the Investigation Workspace:
   - Show the observed threshold comparison (`1 access denial on restricted path`).
   - Show the attached raw evidence list.
   - Change the case status from **Open** to **Investigating**, select disposition **Suspicious**, and type an analyst note:
     *`"Verified unauthorized access attempt by sales.demo to HR directory. Confirmed ACL enforcement."`*
   - Click **Update Case** and show that the notes and status persist permanently in the database audit log.
3. Click **Print / Save PDF** under **Reports** to display a structured executive case file.

### Part 5: User Behavior Analysis (UBA) & Machine Learning (3 Minutes)
1. Navigate to **Rules & UBA**.
2. Show the **Isolation Forest Model** card:
   - Point out the feature schema: `total_events`, `file_access_count`, `distinct_sensitive_files`, `denied_ratio`, `after_hours_ratio`, `distinct_paths`, `device_novelty`.
   - Explain the **Cold-Start Policy**: When an employee has fewer than 24 time-windows of activity, the system displays **"Collecting baseline"** rather than fabricating an artificial risk score.
   - Click **Train Model on Stored Windows** to demonstrate training the Isolation Forest on CPU in under 2 seconds.

---

## 3. Anticipated Questions from Teachers & How to Answer

- **Q: Why SQLite instead of Elasticsearch or Splunk?**  
  *Answer:* *"Elasticsearch and Splunk require 4–8 GB of dedicated RAM, which would overwhelm a student laptop hosting multiple virtual machines. AD Monitor uses SQLite with Write-Ahead Logging (WAL) and indexed queries, delivering sub-millisecond query performance on an 8 GB host with zero background overhead."*

- **Q: How does the system prevent duplicate alerts if network packets are resent?**  
  *Answer:* *"Every event is assigned an immutable SHA-256 fingerprint derived from the source computer, provider, channel, record ID, and event timestamp. Ingestion uses a transactional inbox with unique constraints, ensuring 100% idempotent deduplication."*

- **Q: Is the anomaly score a probability that the user is a malicious hacker?**  
  *Answer:* *"No. In strict accordance with cybersecurity best practices, an anomaly score represents statistical divergence from an established behavioral baseline, not proof of malicious intent. Alerts clearly cite the contributing factors for human analyst verification."*
