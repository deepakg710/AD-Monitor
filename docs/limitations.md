# AD Monitor — Technical Limitations & Operational Scope

In accordance with academic rigor and engineering honesty, this document catalogs the explicit technical boundaries, architectural constraints, and operational limitations of AD Monitor.

## 1. Machine Learning & Sample Size Limitations
- **Small-Lab Sample Distribution:** In a laboratory setting with 1–2 employee VMs, baseline distributions are necessarily sparse. While the Isolation Forest model accurately identifies deviations on simulated or historical datasets, establishing statistically robust individual baselines in enterprise environments typically requires 14–30 days of active telemetry.
- **Cold-Start Policy:** AD Monitor strictly refuses to compute anomaly scores for users with fewer than 24 observation windows. During this phase, the system honestly reports `"Collecting baseline"` and relies exclusively on deterministic security rules.

## 2. Telemetry & Sensor Attribution Boundaries
- **Share Auditing vs. Client Execution:** Access to shared demo files is recorded on the Domain Controller hosting the SMB share (`WIN-8IIRPFSV4GI`), not on the client. AD Monitor correlates the DC-side access event with the client's interactive session via logon ID, workstation name, and IP address. In environments where Kerberos ticket-granting sessions span multiple machines without explicit workstation tracking, client attribution is reported as *Uncertain* rather than fabricated.
- **USB Storage vs. File Transfers:** Detecting USB drive insertion via Windows PnP or WMI does not inherently prove that files were transferred. AD Monitor logs device connection and disconnection as distinct presence events. A file transfer alert is only raised if an instrumented file operation or observed destination write correlates with the removable drive volume letter.
- **Network & Download Attribution:** Standard Windows socket counters measure raw interface throughput but cannot inspect encrypted HTTPS payloads or identify which browser tab initiated a download without specialized endpoint kernel drivers or browser extensions. AD Monitor reports network byte counts only for measured, instrumented operations.

## 3. Infrastructure & Host Sizing
- **Host Resource Footprint:** Designed to run comfortably on an 8 GB RAM physical laptop hosting a Windows Server 2022 DC VM. It intentionally excludes heavyweight distributed streaming systems (Kafka, Elasticsearch, Kubernetes).
- **SQLite Concurrency:** SQLite in WAL mode allows concurrent readers alongside a serialized writer. Ingestion and background rule evaluation use immediate transactions with a 15-second busy timeout. This is optimal for labs with up to 100 events/second, but multi-node enterprise deployments would migrate to PostgreSQL.
