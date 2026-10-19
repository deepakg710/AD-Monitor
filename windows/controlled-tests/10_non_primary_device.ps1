<#
.SYNOPSIS
    Test Scenario 10: Sensitive Share Access from Non-Primary Device
.DESCRIPTION
    Tests access to sensitive folders from a workstation not marked as the user's primary assigned workstation.
#>

$root = "\\WIN-8IIRPFSV4GI.lab.local\ADMonitor-Demo\Sensitive"
if (-not (Test-Path $root)) {
    $root = "C:\ADMonitor-Demo\Sensitive"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 10: Non-Primary Device Access" -ForegroundColor Cyan
Write-Host " Running on Host: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host " User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "[*] Accessing sensitive share from host $env:COMPUTERNAME..." -ForegroundColor Yellow
try {
    $item = Get-ChildItem -Path $root -ErrorAction Stop | Select-Object -First 1
    Write-Host "[PASS] Successfully accessed sensitive item: $($item.Name)" -ForegroundColor Green
    Write-Host "[INFO] If host $env:COMPUTERNAME is not the configured primary device for $env:USERNAME, an alert is raised." -ForegroundColor Cyan
} catch {
    Write-Warning "[-] Share access failed: $($_.Exception.Message)"
}
