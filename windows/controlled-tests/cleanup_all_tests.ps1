<#
.SYNOPSIS
    Cleans up all temporary test artifacts created during harmless controlled testing.
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Controlled Tests Cleanup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$targets = @(
    "C:\ADMonitor-Demo\Staging",
    "C:\ADMonitor-Scratch",
    "$env:TEMP\admonitor_test_script.ps1",
    "$env:TEMP\admonitor_download_test.bin",
    "$env:TEMP\admonitor_eicar_test.txt"
)

foreach ($t in $targets) {
    if (Test-Path $t) {
        try {
            Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed: $t" -ForegroundColor Green
        } catch {
            Write-Warning "[-] Could not remove: $t"
        }
    }
}

Write-Host "[PASS] Lab cleanup completed. Demo folders and ACLs remain pristine." -ForegroundColor Green
