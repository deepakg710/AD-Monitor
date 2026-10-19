<#
.SYNOPSIS
    Test Scenario 03: Canary Document Access
.DESCRIPTION
    Attempts to read the designated decoy canary document.
    Triggers the high-fidelity 'Canary document accessed' rule.
#>

$canaryPath = "\\WIN-8IIRPFSV4GI.lab.local\ADMonitor-Demo\Sensitive\Canary-Payroll-Confidential.txt"
if (-not (Test-Path $canaryPath)) {
    $canaryPath = "C:\ADMonitor-Demo\Sensitive\Canary-Payroll-Confidential.txt"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 03: Canary Document Access" -ForegroundColor Cyan
Write-Host " Target Canary: $canaryPath" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (Test-Path $canaryPath) {
    try {
        $content = Get-Content -Path $canaryPath -ErrorAction Stop
        Write-Host "[+] Canary document touched. Content preview: '$content'" -ForegroundColor Green
        Write-Host "[INFO] Immediate high-priority canary alert expected in AD Monitor." -ForegroundColor Yellow
    } catch {
        Write-Warning "[-] Access to canary failed: $($_.Exception.Message)"
    }
} else {
    Write-Warning "[-] Canary file does not exist at $canaryPath. Run setup_lab.ps1 first."
}
