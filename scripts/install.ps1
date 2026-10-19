<#
.SYNOPSIS
    AD Monitor - Windows PowerShell Installer
#>
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Environment Setup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Virtual environment
$venvPath = Join-Path $root ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Yellow
    & python -m venv $venvPath
}

$pyExe = Join-Path $venvPath "Scripts\python.exe"
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
& $pyExe -m pip install --upgrade pip
& $pyExe -m pip install -r "$root\requirements.txt"

# 2. Frontend Build
$frontendDir = Join-Path $root "frontend"
if (Test-Path $frontendDir) {
    Push-Location $frontendDir
    try {
        Write-Host "[*] Installing frontend dependencies..." -ForegroundColor Yellow
        & npm.cmd install
        Write-Host "[*] Building React SPA with Vite..." -ForegroundColor Yellow
        & npm.cmd run build
        Write-Host "[PASS] Frontend built successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Frontend build error: $($_.Exception.Message)"
    } finally {
        Pop-Location
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "Execute scripts\start.bat or scripts\start.ps1 to launch." -ForegroundColor Cyan
