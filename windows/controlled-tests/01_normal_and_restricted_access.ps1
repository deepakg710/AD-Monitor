<#
.SYNOPSIS
    Test Scenario 01: Normal Sales Access and Denied HR Attempt
.DESCRIPTION
    Runs on Employee VM LAB-PC01 as LAB\sales.demo.
    Reads an authorized Sales file (Success), then attempts an unauthorized HR file (Denied).
#>

$root = "\\WIN-8IIRPFSV4GI.lab.local\ADMonitor-Demo"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 01: Sales Access (OK) & HR Access (Denied)" -ForegroundColor Cyan
Write-Host " Running as: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Authorized read
Write-Host "[*] Step 1: Reading authorized Sales document..." -ForegroundColor Yellow
$salesFile = "$root\Sales\Demo-File-1.txt"
try {
    $content = Get-Content -Path $salesFile -TotalCount 1 -ErrorAction Stop
    Write-Host "[PASS] Successfully read Sales file: '$content'" -ForegroundColor Green
} catch {
    Write-Warning "[-] Sales read failed: $($_.Exception.Message)"
}

# 2. Unauthorized read (expected to fail with Access Denied)
Write-Host "`n[*] Step 2: Attempting unauthorized HR document..." -ForegroundColor Yellow
$hrFile = "$root\HR\Demo-File-1.txt"
try {
    $content = Get-Content -Path $hrFile -TotalCount 1 -ErrorAction Stop
    Write-Warning "[!] Warning: HR file was read successfully. Check ACL configuration."
} catch {
    Write-Host "[PASS] HR access denied as expected: $($_.Exception.Message)" -ForegroundColor Green
    Write-Host "[INFO] Event 4656 / 4663 / 5145 with Failure result should be recorded on DC." -ForegroundColor Cyan
}
