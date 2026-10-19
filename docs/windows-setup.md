# AD Monitor — Windows Lab Setup Guide

This guide details the specific setup requirements and deployment steps for each machine in the authorized college lab.

## 1. Machine Inventory & Roles

| Machine Name | Operating System | Role | IP / Network | Actions Required |
| --- | --- | --- | --- | --- |
| `DESKTOP-IAUT7R9` | Windows 10/11 (Physical Host) | Hosts AD Monitor Web App, FastAPI backend, SQLite DB, and DC VM | Private Host IP (e.g. `192.168.77.1` or LAN) | Run `scripts/install.bat` and `scripts/start.bat` |
| `WIN-8IIRPFSV4GI` | Windows Server 2022 (DC VM) | Domain Controller (`lab.local`), SMB Demo File Server, WEF Collector | `192.168.77.10/24` | Run `setup_lab.ps1`, `wef_bridge.ps1`, `ad_sync.ps1` |
| `LAB-PC01` | Windows 11 Pro (Employee VM) | Monitored employee workstation; runs user actions as `LAB\sales.demo` | `192.168.77.20/24` | Run `install_agent.ps1` and controlled test scripts |
| `DESKTOP-IACNTNH` | Windows 10 Pro (Friend's Laptop) | Hypervisor host for employee VM | Private LAN | VM hosting only. **Do NOT install monitoring agents here.** |

---

## 2. Step-by-Step Installation

### Step 1: Start AD Monitor on Host Laptop (`DESKTOP-IAUT7R9`)
1. Open PowerShell or Command Prompt.
2. Navigate to the project root:
   ```cmd
   cd C:\path\to\AD-Monitor
   ```
3. Run the installer:
   ```cmd
   scripts\install.bat
   ```
4. Start the application:
   ```cmd
   scripts\start.bat
   ```
5. Open your browser and navigate to `http://localhost:8000`.
6. Complete the **First Administrator Setup** by creating your initial username and password (e.g., `admin` / `YourSecurePassword123!`).

---

### Step 2: Configure the Domain Controller (`WIN-8IIRPFSV4GI`)
1. Log in to the DC VM as Domain Administrator (`LAB\Administrator`).
2. Copy the `windows/` folder to `C:\ADMonitor` on the DC.
3. Open an **Elevated PowerShell** window.
4. Run the lab setup script to create the 6 department folders (`Sales`, `HR`, `Finance`, `IT`, `Management`, `Sensitive`), generate the 120 dummy files, configure the Canary document, and check SMB share permissions:
   ```powershell
   cd C:\ADMonitor\setup
   .\setup_lab.ps1
   ```
5. In the AD Monitor Web Dashboard:
   - Navigate to **Diagnostics** &rarr; **Enroll Collector**.
   - Name: `DC WEF Bridge`, Type: `wef`, Expected Host: `WIN-8IIRPFSV4GI`.
   - Copy the generated Bearer Token.
6. Start the WEF Collector Bridge on the DC:
   ```powershell
   cd C:\ADMonitor\collector
   .\wef_bridge.ps1 -BackendUrl "http://192.168.77.1:8000" -CollectorToken "YOUR_COLLECTOR_TOKEN"
   ```
7. Perform an initial Active Directory inventory sync:
   ```powershell
   cd C:\ADMonitor\setup
   .\ad_sync.ps1 -BackendUrl "http://192.168.77.1:8000" -CollectorToken "YOUR_COLLECTOR_TOKEN"
   ```

---

### Step 3: Configure the Employee VM (`LAB-PC01`)
1. Log in to the Employee VM as `LAB\sales.demo`.
2. Copy the `windows/` folder to `C:\ADMonitor` on `LAB-PC01`.
3. In the AD Monitor Web Dashboard:
   - Navigate to **Diagnostics** &rarr; **Enroll Collector**.
   - Name: `Employee VM Agent`, Type: `endpoint`, Expected Host: `LAB-PC01`.
   - Copy the generated Bearer Token.
4. In an Elevated PowerShell window, install the persistent background monitoring agent:
   ```powershell
   cd C:\ADMonitor\agent
   .\install_agent.ps1 -BackendUrl "http://192.168.77.1:8000" -AgentToken "YOUR_AGENT_TOKEN"
   ```
5. Verify on the dashboard that `LAB-PC01` shows an **Online** status badge with live CPU, RAM, and Disk metrics.
