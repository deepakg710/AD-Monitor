<#
.SYNOPSIS
    Test Scenario 02: Bulk Sensitive-File Reads
.DESCRIPTION
    Reads 12 distinct sensitive documents in rapid succession within 30 seconds.
    Triggers the 'Bulk sensitive file reads' rule (threshold: 10 distinct files).
#>

$root = "\\WIN-8IIRPFSV4GI.lab.local\ADMonitor-Demo\Sensitive"
if (-not (Test-Path $root)) {
    $root = "C:\ADMonitor-Demo\Sensitive"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 02: Bulk Sensitive Reads" -ForegroundColor Cyan
Write-Host " Target Path: $root" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$count = 0
for ($i = 1; $i -le 15; $i++) {
    $target = "$root\Demo-File-$i.txt"
    if (Test-Path $target) {
        $c = Get-Content -Path $target -TotalCount 1 -ErrorAction SilentlyContinue
        Write-Host "[$i/15] Read $target" -ForegroundColor Gray
        $count++
    }
}

Write-Host "[+] Completed bulk read of $count distinct files." -ForegroundColor Green
Write-Host "[INFO] AD Monitor will correlate distinct object paths in the window and trigger a 'Medium' severity alert." -ForegroundColor Cyan
