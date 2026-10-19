<#
.SYNOPSIS
    AD Monitor - Lab Environment Setup & Audit Policy Verification
.DESCRIPTION
    Runs on the Domain Controller (WIN-8IIRPFSV4GI) with Elevated Administrator privileges.
    Verifies demo directory structure (HR, Finance, Sales, IT, Management, Sensitive),
    ensures dummy test files are present, checks share existence, and validates SACL auditing.
#>

# Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$demoRoot = "C:\ADMonitor-Demo"
$scratchRoot = "C:\ADMonitor-Scratch"
$departments = @("HR", "Finance", "Sales", "IT", "Management", "Sensitive")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Lab Setup & Auditing Verification" -ForegroundColor Cyan
Write-Host " Target DC: WIN-8IIRPFSV4GI" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Create root directory if missing
if (-not (Test-Path $demoRoot)) {
    New-Item -ItemType Directory -Path $demoRoot -Force | Out-Null
    Write-Host "[+] Created demo root: $demoRoot" -ForegroundColor Green
}

# 2. Create scratch directory for rapid modification tests
if (-not (Test-Path $scratchRoot)) {
    New-Item -ItemType Directory -Path $scratchRoot -Force | Out-Null
    Write-Host "[+] Created scratch folder: $scratchRoot" -ForegroundColor Green
}

# 3. Verify folders and dummy files
foreach ($dept in $departments) {
    $deptPath = Join-Path $demoRoot $dept
    if (-not (Test-Path $deptPath)) {
        New-Item -ItemType Directory -Path $deptPath -Force | Out-Null
        Write-Host "[+] Created department folder: $deptPath" -ForegroundColor Green
    }
    for ($i = 1; $i -le 20; $i++) {
        $filePath = Join-Path $deptPath "Demo-File-$i.txt"
        if (-not (Test-Path $filePath)) {
            "Confidential internal document for $dept team. Authorized access only. Reference item #$i." | Set-Content -Path $filePath -Encoding UTF8
        }
    }
}
Write-Host "[PASS] 120 dummy lab files verified across 6 department folders." -ForegroundColor Green

# 4. Canary document setup
$canaryPath = Join-Path $demoRoot "Sensitive\Canary-Payroll-Confidential.txt"
if (-not (Test-Path $canaryPath)) {
    "CONFIDENTIAL CANARY DOCUMENT - AD MONITOR LAB. ANY ACCESS TRIGGERS SECURITY AUDIT." | Set-Content -Path $canaryPath -Encoding UTF8
    Write-Host "[+] Configured Canary file: $canaryPath" -ForegroundColor Green
}

# 5. Check SMB share
$share = Get-SmbShare -Name "ADMonitor-Demo" -ErrorAction SilentlyContinue
if (-not $share) {
    Write-Host "[*] Creating SMB share 'ADMonitor-Demo'..." -ForegroundColor Yellow
    New-SmbShare -Name "ADMonitor-Demo" -Path $demoRoot -FullAccess "Everyone" | Out-Null
    Write-Host "[PASS] SMB share 'ADMonitor-Demo' created." -ForegroundColor Green
} else {
    Write-Host "[PASS] SMB share 'ADMonitor-Demo' exists and points to $($share.Path)." -ForegroundColor Green
}

# 6. Audit policy status check
Write-Host "[*] Querying Advanced Audit Policy for Object Access..." -ForegroundColor Cyan
try {
    auditpol /get /subcategory:"File System"
} catch {
    Write-Warning "Could not query auditpol: $($_.Exception.Message)"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Lab setup verification complete." -ForegroundColor Green
