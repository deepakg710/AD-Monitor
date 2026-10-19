<#
.SYNOPSIS
    Test Scenario 09: Rapid File Modifications
.DESCRIPTION
    Creates and rapidly renames 16 disposable files in C:\ADMonitor-Scratch.
    Tests ransomware-like modification detection without touching any real user files or using encryption.
#>

$scratchDir = "C:\ADMonitor-Scratch"
if (-not (Test-Path $scratchDir)) {
    New-Item -ItemType Directory -Path $scratchDir -Force | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 09: Rapid File Modifications (Harmless Disposable)" -ForegroundColor Cyan
Write-Host " Scratch Directory: $scratchDir" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Create 16 temporary files
for ($i = 1; $i -le 16; $i++) {
    $f = "$scratchDir\scratch_$i.txt"
    "Harmless test record $i" | Set-Content -Path $f -Encoding UTF8
}
Write-Host "[+] Created 16 disposable files in scratch directory." -ForegroundColor Gray

# 2. Rapidly rename them
for ($i = 1; $i -le 16; $i++) {
    $orig = "$scratchDir\scratch_$i.txt"
    $renamed = "$scratchDir\scratch_${i}_modified.bak"
    Rename-Item -Path $orig -NewName $renamed -Force
}
Write-Host "[PASS] Rapid modification and rename completed on 16 files." -ForegroundColor Green
Write-Host "[INFO] Triggers 'Rapid file modifications' rule (threshold: 15)." -ForegroundColor Cyan

# Cleanup
Get-ChildItem -Path $scratchDir -Filter "scratch_*" | Remove-Item -Force
Write-Host "[+] Cleaned up test files." -ForegroundColor Gray
