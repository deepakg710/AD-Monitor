<#
.SYNOPSIS
    Controlled Attack Scenario: Privilege Escalation Attempt from Employee Workstation
.DESCRIPTION
    Runs on Employee VM (LAB-PC01).
    Attempts unauthorized addition of 'sales.demo' into privileged administrative groups
    (Local Administrators & Domain Admins) and reports the privilege attack telemetry.
#>

param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = "admon-lab-pc01-agent-token-2026"
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " ATTACK DEMO: Privilege Escalation Attempt (from Workstation)" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

$targetUser = "sales.demo"
$privGroup = "Domain Admins"

Write-Host "[*] Step 1: Attempting local privilege escalation on LAB-PC01..." -ForegroundColor Yellow
Write-Host "    Executing: net localgroup Administrators $targetUser /add" -ForegroundColor Gray
$null = net localgroup Administrators $targetUser /add 2>&1

Write-Host "[*] Step 2: Attempting domain privilege escalation over RPC/SMB..." -ForegroundColor Yellow
Write-Host "    Executing: net group `"$privGroup`" $targetUser /add /domain" -ForegroundColor Gray
$null = net group "$privGroup" $targetUser /add /domain 2>&1

# Submit privilege change telemetry via endpoint agent
$record = @{
    id = [guid]::NewGuid().ToString()
    kind = "observation"
    time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
    data = @{
        category = "privilege_change"
        target_group = $privGroup
        member = "LAB\$targetUser"
        action = "group_member_add"
        command_line = "net group `"$privGroup`" $targetUser /add /domain"
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
    Write-Host "[PASS] Privilege escalation attack executed and telemetry delivered!" -ForegroundColor Green
    Write-Host "[INFO] Check AD Monitor dashboard for alert: 'Privileged Group Membership Modified'." -ForegroundColor Cyan
} catch {
    Write-Host "[-] Ingestion notification failed: $($_.Exception.Message)" -ForegroundColor Red
}
