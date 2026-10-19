<#
.SYNOPSIS
    Test Scenario 06: Removable Storage (USB) Copy Simulation
.DESCRIPTION
    Checks for connected removable USB drives and copies a dummy file, or simulates an instrumented copy event.
#>

param(
    [string]$RemovableDriveLetter = ""
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Scenario 06: Removable Storage File Transfer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Find removable drive if not provided
if (-not $RemovableDriveLetter) {
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($drive) {
        $RemovableDriveLetter = $drive.DeviceID
    }
}

if ($RemovableDriveLetter) {
    Write-Host "[+] Detected removable drive: $RemovableDriveLetter" -ForegroundColor Green
    $dest = "$RemovableDriveLetter\ADMonitor-Demo-Copy.txt"
    "Dummy confidential file copied to removable USB storage for test verification." | Set-Content -Path $dest -Encoding UTF8
    Write-Host "[PASS] Copied test file to USB drive: $dest" -ForegroundColor Green
} else {
    Write-Host "[INFO] No physical USB drive detected. Endpoint agent records USB connection/disconnection whenever hardware is attached." -ForegroundColor Yellow
    Write-Host "[INFO] For demonstration without physical USB, the endpoint agent reports 'present_at_start' or insertion events." -ForegroundColor Gray
}
