<#
.SYNOPSIS
    Controlled Attack Scenario: File Copy to Pendrive / Removable Storage
.DESCRIPTION
    Runs on Employee VM (LAB-PC01).
    Detects physical USB removable drive or simulates removable storage transfer.
    Copies confidential HR/Sales records to removable storage.
#>

param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = "admon-lab-pc01-agent-token-2026"
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " ATTACK DEMO: Data Exfiltration to Removable USB Storage" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

# 1. Search for real removable drive
$usbDrive = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue | Select-Object -First 1

$sourceFile = "C:\ADMonitor-Demo\HR\Demo-File-1.txt"
if (-not (Test-Path $sourceFile)) {
    $sourceFile = "C:\Windows\System32\drivers\etc\hosts"
}

if ($usbDrive) {
    $dest = "$($usbDrive.DeviceID)\Confidential-HR-Payroll.txt"
    Write-Host "[+] Real USB flash drive detected at $($usbDrive.DeviceID)" -ForegroundColor Green
    Write-Host "[*] Copying sensitive file to USB drive: $dest" -ForegroundColor Yellow
    Copy-Item -Path $sourceFile -Destination $dest -Force
    Write-Host "[+] File copied to physical USB successfully!" -ForegroundColor Green
} else {
    Write-Host "[INFO] No physical USB plugged in. Simulating USB file transfer..." -ForegroundColor Yellow
    $dest = "E:\Confidential-HR-Payroll.txt"
}

# Report instrumented file_copy to AD Monitor
$record = @{
    id = [guid]::NewGuid().ToString()
    kind = "observation"
    time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
    data = @{
        category = "file_copy"
        source_path = $sourceFile
        destination_path = $dest
        destination_removable = $true
        bytes = 4096
        action = "copy_to_removable_drive"
    }
}

$payload = @{
    records = @($record)
} | ConvertTo-Json -Depth 5

$headers = @{
    "Authorization" = "Bearer $AgentToken"
    "Content-Type" = "application/json"
}

try {
    $res = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $payload
    Write-Host "[PASS] Removable storage transfer recorded by endpoint agent!" -ForegroundColor Green
    Write-Host "[INFO] Check AD Monitor dashboard for alert: 'Copy to removable storage observed'." -ForegroundColor Cyan
} catch {
    Write-Host "[-] Ingestion notification failed: $($_.Exception.Message)" -ForegroundColor Red
}
