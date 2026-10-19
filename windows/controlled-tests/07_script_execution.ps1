<#
.SYNOPSIS
    Test Scenario 07: Controlled PowerShell Script Execution
.DESCRIPTION
    Runs a harmless controlled script block to trigger PowerShell Script Block Logging (Event 4104).
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 07: Controlled Harmless Script Block Execution" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptContent = @'
Write-Host "AD Monitor controlled test script block running." -ForegroundColor Green
$testVar = "Harmless metadata test payload"
Get-Process -Id $PID | Select-Object Id, ProcessName
'@

$tempScript = "$env:TEMP\admonitor_test_script.ps1"
$scriptContent | Set-Content -Path $tempScript -Encoding UTF8

Write-Host "[*] Executing script: $tempScript" -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tempScript

Remove-Item $tempScript -Force
Write-Host "[PASS] Script executed and cleaned up." -ForegroundColor Green
Write-Host "[INFO] Generates PowerShell 4104 event for correlation with downloads." -ForegroundColor Cyan
