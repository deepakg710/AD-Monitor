<#
.SYNOPSIS
    Runs automated pytest test suite for AD Monitor.
#>
$root = Resolve-Path "$PSScriptRoot\.."
$env:PYTHONPATH = "$root"

$pyExe = "python"
if (Test-Path "$root\.venv\Scripts\python.exe") {
    $pyExe = "$root\.venv\Scripts\python.exe"
} elseif (Test-Path "$root\..\..\work\.venv\Scripts\python.exe") {
    $pyExe = "$root\..\..\work\.venv\Scripts\python.exe"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Test Suite Execution" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location $root
& $pyExe -m pytest -v
