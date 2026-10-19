<#
.SYNOPSIS
    Installs the AD Monitor WEF Collector Bridge as a persistent Windows Scheduled Task.
#>
param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$CollectorToken = ""
)

if (-not $CollectorToken) {
    Write-Error "Please provide -CollectorToken from the AD Monitor dashboard."
    exit 1
}

$taskName = "ADMonitorWEFBridge"
$scriptPath = Join-Path $PSScriptRoot "wef_bridge.ps1"
if (-not (Test-Path $scriptPath)) {
    $scriptPath = "C:\ADMonitor\collector\wef_bridge.ps1"
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -BackendUrl `"$BackendUrl`" -CollectorToken `"$CollectorToken`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "AD Monitor WEF Collector Bridge" -Force

Write-Host "[+] Scheduled task '$taskName' registered successfully." -ForegroundColor Green
Write-Host "[+] Starting task..." -ForegroundColor Green
Start-ScheduledTask -TaskName $taskName
