<#
.SYNOPSIS
    Stops running Uvicorn/AD Monitor backend processes.
#>
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "backend.api:app" } | Stop-Process -Force
Write-Host "[+] AD Monitor server processes stopped." -ForegroundColor Green
