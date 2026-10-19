<#
.SYNOPSIS
    Controlled Attack Scenario: Command & Control (C2) Periodic Beaconing
.DESCRIPTION
    Runs on Employee VM (LAB-PC01).
    Simulates a compromised workstation process establishing regular, low-jitter
    outbound heartbeat/beacon pulses to an external Command & Control server.
#>

param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = "admon-lab-pc01-agent-token-2026",
    [string]$C2Destination = "198.51.100.45:443"
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " ATTACK DEMO: Command & Control (C2) Periodic Beaconing" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

Write-Host "[*] Simulating malware process beaconing to external C2: $C2Destination" -ForegroundColor Yellow
$pulses = 5

for ($i = 1; $i -le $pulses; $i++) {
    Write-Host "[*] Sending C2 beacon pulse $i of $pulses (Interval: 3s)..." -ForegroundColor Yellow

    $record = @{
        id = [guid]::NewGuid().ToString()
        kind = "observation"
        time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        data = @{
            category = "network_connection"
            c2_destination = $C2Destination
            beacon = $true
            interval_seconds = 3
            jitter_percent = 2.1
            protocol = "HTTPS"
            remote_ip = "198.51.100.45"
            remote_port = 443
            process_name = "powershell.exe"
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
        $null = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $payload
        Write-Host "  [+] Pulse $i delivered." -ForegroundColor Green
    } catch {
        Write-Host "  [-] Pulse $i delivery failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($i -lt $pulses) {
        Start-Sleep -Seconds 3
    }
}

Write-Host "[PASS] C2 Beaconing attack simulation complete!" -ForegroundColor Green
Write-Host "[INFO] Check AD Monitor dashboard for alert: 'Command & Control (C2) Periodic Beaconing'." -ForegroundColor Cyan
