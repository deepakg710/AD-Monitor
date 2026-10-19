param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [Parameter(Mandatory=$true)][string]$AgentToken
)

$agentDir = "C:\ADMonitor\agent"
if (-not (Test-Path $agentDir)) {
    New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
}

$agentScript = Join-Path $agentDir "endpoint_agent.ps1"
if (-not (Test-Path $agentScript)) {
    Invoke-WebRequest "$BackendUrl/lab-scripts/endpoint_agent.ps1" -UseBasicParsing -OutFile $agentScript
}

# Store token encrypted with Windows DPAPI scoped to current user/account
$tokenFile = Join-Path $agentDir "token.dpapi"
$secToken = ConvertTo-SecureString $AgentToken -AsPlainText -Force
$secToken | ConvertFrom-SecureString | Set-Content -Path $tokenFile -Encoding UTF8

$batContent = @"
@echo off
start "" /b powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "$agentScript" -BackendUrl "$BackendUrl" -TokenFile "$tokenFile"
"@

$batPath = Join-Path $agentDir "start_agent.bat"
Set-Content -Path $batPath -Value $batContent

# Add to user Startup folder (runs automatically on Windows boot/login)
$startupFolder = [Environment]::GetFolderPath('Startup')
Copy-Item -Path $batPath -Destination (Join-Path $startupFolder "ADMonitorAgent.bat") -Force

# Add to Desktop
$desktopFolder = [Environment]::GetFolderPath('Desktop')
Copy-Item -Path $batPath -Destination (Join-Path $desktopFolder "Start-ADMonitor-Agent.bat") -Force

# Start it immediately
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batPath`""

Write-Host "[+] DPAPI token stored at: $tokenFile" -ForegroundColor Green
Write-Host "[+] Permanent autostart configured in: $startupFolder" -ForegroundColor Green
Write-Host "[+] Desktop shortcut created: Start-ADMonitor-Agent.bat" -ForegroundColor Green
Write-Host "[+] Endpoint Agent started in background!" -ForegroundColor Green
