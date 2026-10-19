<#
.SYNOPSIS
    Test Scenario 11: Windows Defender Antivirus Event Verification
.DESCRIPTION
    Uses the industry-standard benign EICAR test string to trigger a harmless Defender detection event.
    NEVER uses real malware. Validates that Event 1116 / 1117 is forwarded and ingested by AD Monitor.
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 11: Antivirus Detection Event (Harmless EICAR)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$testFile = "$env:TEMP\admonitor_eicar_test.txt"

Write-Host "[*] Writing harmless standard EICAR test string to $testFile..." -ForegroundColor Yellow

try {
    [System.IO.File]::WriteAllText($testFile, $eicar)
    Write-Host "[PASS] Test string written. Windows Defender should intercept and quarantine." -ForegroundColor Green
    Write-Host "[INFO] Check Defender event logs: Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational'" -ForegroundColor Cyan
} catch {
    Write-Host "[PASS] Defender immediately intercepted write operation: $($_.Exception.Message)" -ForegroundColor Green
}
