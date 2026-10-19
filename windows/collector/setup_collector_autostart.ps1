param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [Parameter(Mandatory=$true)][string]$CollectorToken
)

$collectorDir = "C:\ADMonitor\collector"
if (-not (Test-Path $collectorDir)) {
    New-Item -ItemType Directory -Path $collectorDir -Force | Out-Null
}

$bridgeScript = Join-Path $collectorDir "wef_bridge.ps1"
if (-not (Test-Path $bridgeScript)) {
    Invoke-WebRequest "$BackendUrl/lab-scripts/wef_bridge.ps1" -UseBasicParsing -OutFile $bridgeScript
}

# Store token encrypted with Windows DPAPI
$tokenFile = Join-Path $collectorDir "token.dpapi"
$secToken = ConvertTo-SecureString $CollectorToken -AsPlainText -Force
$secToken | ConvertFrom-SecureString | Set-Content -Path $tokenFile -Encoding UTF8

$batContent = @"
@echo off
start "" powershell -ExecutionPolicy Bypass -File "$bridgeScript" -BackendUrl "$BackendUrl" -TokenFile "$tokenFile"
"@

$batPath = Join-Path $collectorDir "start_bridge.bat"
Set-Content -Path $batPath -Value $batContent

# Add to user Startup folder
$startupFolder = [Environment]::GetFolderPath('Startup')
Copy-Item -Path $batPath -Destination (Join-Path $startupFolder "ADMonitorBridge.bat") -Force

# Add to Desktop
$desktopFolder = [Environment]::GetFolderPath('Desktop')
Copy-Item -Path $batPath -Destination (Join-Path $desktopFolder "Start-ADMonitor-Bridge.bat") -Force

# Start it immediately
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batPath`""

Write-Host "[+] DPAPI token stored at: $tokenFile" -ForegroundColor Green
Write-Host "[+] Permanent autostart configured in: $startupFolder" -ForegroundColor Green
Write-Host "[+] Desktop shortcut created: Start-ADMonitor-Bridge.bat" -ForegroundColor Green
Write-Host "[+] DC WEF Bridge started!" -ForegroundColor Green
