<#
.SYNOPSIS
    AD Monitor - Host & Environment Prerequisites Check
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Prerequisites Verification" -ForegroundColor Cyan
Write-Host " Host: $env:COMPUTERNAME ($([System.Environment]::OSVersion.VersionString))" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$allPass = $true

# 1. Python check
try {
    $pyVer = & python --version 2>&1
    Write-Host "[PASS] Python installed: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Python not found on standard PATH. Check virtual environment or custom install." -ForegroundColor Yellow
    $allPass = $false
}

# 2. Node check
try {
    $nodeVer = & node -v 2>&1
    Write-Host "[PASS] Node.js installed: $nodeVer" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Node.js not detected on PATH." -ForegroundColor Yellow
}

# 3. Memory check
$ram = Get-CimInstance Win32_OperatingSystem
$totalGb = [math]::Round($ram.TotalVisibleMemorySize / 1024 / 1024, 1)
$freeGb = [math]::Round($ram.FreePhysicalMemory / 1024 / 1024, 1)
Write-Host "[INFO] Host Physical Memory: $totalGb GB Total ($freeGb GB Available)" -ForegroundColor Cyan
if ($totalGb -lt 6.0) {
    Write-Warning "Host memory is below 8 GB. Run lightweight configuration alongside VMs."
}

# 4. WinRM check (if on DC or client)
try {
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq "Running") {
        Write-Host "[PASS] WinRM service is Running." -ForegroundColor Green
    } else {
        Write-Host "[INFO] WinRM service is $($winrm.Status)." -ForegroundColor Gray
    }
} catch {}

# 5. WEF Collector service (Wecsvc)
try {
    $wec = Get-Service Wecsvc -ErrorAction SilentlyContinue
    if ($wec) {
        Write-Host "[INFO] Windows Event Collector service (Wecsvc): $($wec.Status)" -ForegroundColor Gray
    }
} catch {}

Write-Host "==========================================================" -ForegroundColor Cyan
if ($allPass) {
    Write-Host "Prerequisites check completed. Environment is ready for AD Monitor." -ForegroundColor Green
} else {
    Write-Host "Some optional dependencies require attention. See above." -ForegroundColor Yellow
}
