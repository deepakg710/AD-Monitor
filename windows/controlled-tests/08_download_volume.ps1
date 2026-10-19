<#
.SYNOPSIS
    Test Scenario 08: Measured Download Volume
.DESCRIPTION
    Simulates high-volume data retrieval through measured instrumented download.
#>

param(
    [string]$BackendUrl = "http://127.0.0.1:8000",
    [string]$AgentToken = ""
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 08: Measured Download Volume Simulation" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Create a local 12 MB test dummy buffer
$testBytes = 12 * 1024 * 1024
$destPath = "$env:TEMP\admonitor_download_test.bin"

Write-Host "[*] Creating 12 MB measured dummy download payload..." -ForegroundColor Yellow
$dummy = New-Object byte[] (1024 * 1024)
$fs = [System.IO.File]::Create($destPath)
for ($i = 0; $i -lt 12; $i++) {
    $fs.Write($dummy, 0, $dummy.Length)
}
$fs.Close()

Write-Host "[PASS] Measured download complete: $destPath ($testBytes bytes)" -ForegroundColor Green

if ($AgentToken) {
    # Send instrumented observation to backend
    $payload = @{
        kind = "observation"
        id = [guid]::NewGuid().ToString()
        data = @{
            category = "download"
            hostname = $env:COMPUTERNAME
            time = [DateTime]::UtcNow.ToString("o")
            user_sid = $null
            account = "$env:USERDOMAIN\$env:USERNAME"
            fields = @{
                destination_path = $destPath
                bytes = $testBytes
            }
        }
    }
    $body = @{ transport_id = [guid]::NewGuid().ToString(); records = @($payload) } | ConvertTo-Json -Depth 6
    $headers = @{ "Authorization" = "Bearer $AgentToken"; "Content-Type" = "application/json" }
    try {
        Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $body | Out-Null
        Write-Host "[+] Instrumented download observation submitted to AD Monitor." -ForegroundColor Green
    } catch {}
}

Remove-Item $destPath -Force -ErrorAction SilentlyContinue
