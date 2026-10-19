<#
.SYNOPSIS
    Test Scenario 04: After-Hours Sensitive Access
.DESCRIPTION
    Performs access to sensitive share documents.
    To test this harmlessly during the day:
    1. In AD Monitor web dashboard -> Settings, temporarily set 'Business Start Hour' to a later time
       or remove today's day of week from 'Business Days'.
    2. Run this script.
    3. Verify that 'After-hours sensitive activity' alert is raised without changing the DC system clock.
#>

$target = "\\WIN-8IIRPFSV4GI.lab.local\ADMonitor-Demo\Sensitive\Demo-File-1.txt"
if (-not (Test-Path $target)) {
    $target = "C:\ADMonitor-Demo\Sensitive\Demo-File-1.txt"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 04: After-Hours Sensitive Access Test" -ForegroundColor Cyan
Write-Host " Local Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (Test-Path $target) {
    $content = Get-Content -Path $target -TotalCount 1
    Write-Host "[+] Sensitive document read at current local time." -ForegroundColor Green
    Write-Host "[INFO] If policy is set to consider current time after-hours, an alert will be generated." -ForegroundColor Cyan
} else {
    Write-Warning "[-] Target not found: $target"
}
