<#
.SYNOPSIS
    Starts the canonical AD Monitor server using backend.app:make_app and project-root data/admonitor.db.
#>
$root = Resolve-Path "$PSScriptRoot\.."
$env:PYTHONPATH = "$root"
if (-not $env:ADMONITOR_DB) {
    $env:ADMONITOR_DB = Join-Path $root "data\admonitor.db"
}
if (-not $env:ADMONITOR_ALLOW_LAB_HTTP) {
    $env:ADMONITOR_ALLOW_LAB_HTTP = "1"
}
if (-not $env:ADMONITOR_HOSTS) {
    $env:ADMONITOR_HOSTS = "localhost,127.0.0.1,0.0.0.0,::1,192.168.77.1,desktop-iaut7r9"
}

$pyExe = "python"
if (Test-Path "$root\.venv\Scripts\python.exe") {
    $pyExe = "$root\.venv\Scripts\python.exe"
} elseif (Test-Path "$root\..\..\work\.venv\Scripts\python.exe") {
    $pyExe = "$root\..\..\work\.venv\Scripts\python.exe"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Launching Canonical Application Server" -ForegroundColor Cyan
Write-Host " Database: $env:ADMONITOR_DB" -ForegroundColor Cyan
Write-Host " URL:      http://localhost:8765" -ForegroundColor Cyan
Write-Host " Press Ctrl+C to terminate server." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location $root
Start-Process -FilePath $pyExe -ArgumentList "-m scripts.guardian" -WorkingDirectory $root -WindowStyle Hidden
& $pyExe -m uvicorn backend.app:make_app --factory --host 0.0.0.0 --port 8765 --workers 1
