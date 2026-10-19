<#
.SYNOPSIS
    Test Scenario 05: Data Staging and ZIP Creation
.DESCRIPTION
    Simulates employee data collection by copying 5 authorized dummy files into a staging directory
    and compressing them into a ZIP file.
#>

$sourceDir = "C:\ADMonitor-Demo\Sales"
$stagingDir = "C:\ADMonitor-Demo\Staging"
$zipPath = "C:\ADMonitor-Demo\Staging\Exfil-Archive.zip"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 05: Data Staging and ZIP Compression" -ForegroundColor Cyan
Write-Host " Staging Dir: $stagingDir" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}

# 1. Copy 5 dummy files
for ($i = 1; $i -le 5; $i++) {
    $src = "$sourceDir\Demo-File-$i.txt"
    $dst = "$stagingDir\Demo-File-$i.txt"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Host "[+] Staged $dst" -ForegroundColor Gray
    }
}

# 2. Compress staged files into ZIP
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*.txt" -DestinationPath $zipPath -Force
Write-Host "[PASS] Created archive: $zipPath" -ForegroundColor Green
Write-Host "[INFO] Triggers 'Dummy data staged into an archive' rule." -ForegroundColor Cyan
