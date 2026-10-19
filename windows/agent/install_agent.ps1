<#
.SYNOPSIS
    Installs the AD Monitor Endpoint Agent as a persistent Windows Scheduled Task.
#>
param(
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = ""
)

if (-not $AgentToken) {
    Write-Error "Please provide -AgentToken from the AD Monitor dashboard enroll step."
    exit 1
}

$taskName = "ADMonitorEndpointAgent"
$scriptPath = Join-Path $PSScriptRoot "endpoint_agent.ps1"

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -BackendUrl `"$BackendUrl`" -AgentToken `"$AgentToken`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "AD Monitor Employee VM Endpoint Agent" -Force

Write-Host "[+] Scheduled task '$taskName' registered successfully." -ForegroundColor Green
Write-Host "[+] Starting task..." -ForegroundColor Green
Start-ScheduledTask -TaskName $taskName
