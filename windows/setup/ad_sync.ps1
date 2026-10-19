<#
.SYNOPSIS
    AD Monitor - Active Directory Inventory Sync
.DESCRIPTION
    Runs on the Domain Controller (WIN-8IIRPFSV4GI).
    Extracts users, department groups, group memberships, and computer accounts from AD,
    and posts a complete directory snapshot to the AD Monitor backend.
#>

param (
    [string]$BackendUrl = "http://127.0.0.1:8000",
    [string]$CollectorToken = ""
)

if (-not $CollectorToken) {
    Write-Error "Please specify -CollectorToken."
    exit 1
}

Write-Host "[*] Querying Active Directory inventory..." -ForegroundColor Cyan

$employees = @()
$groups = @()
$computers = @()

# 1. Query Groups
try {
    $adGroups = Get-ADGroup -Filter * -Properties SID, Name
    foreach ($g in $adGroups) {
        $groups += @{
            sid = $g.SID.Value
            name = $g.Name
        }
    }
} catch {
    Write-Warning "Could not query AD Groups via module: $($_.Exception.Message)"
}

# 2. Query Users
try {
    $adUsers = Get-ADUser -Filter * -Properties SID, SamAccountName, DisplayName, Department, Enabled, MemberOf
    foreach ($u in $adUsers) {
        $grpSids = @()
        foreach ($dn in $u.MemberOf) {
            try {
                $gObj = Get-ADGroup -Identity $dn
                if ($gObj) { $grpSids += $gObj.SID.Value }
            } catch {}
        }
        $employees += @{
            sid = $u.SID.Value
            account = $u.SamAccountName
            name = $u.DisplayName
            department = $u.Department
            enabled = [bool]$u.Enabled
            group_sids = $grpSids
        }
    }
} catch {
    Write-Warning "Could not query AD Users via module: $($_.Exception.Message)"
}

# 3. Query Computers
try {
    $adComps = Get-ADComputer -Filter * -Properties SID, Name, DnsHostName, OperatingSystem, IPv4Address
    foreach ($c in $adComps) {
        $computers += @{
            hostname = if ($c.DnsHostName) { $c.DnsHostName } else { $c.Name }
            sid = $c.SID.Value
            os = $c.OperatingSystem
            ips = @($c.IPv4Address | Where-Object { $_ })
        }
    }
} catch {
    Write-Warning "Could not query AD Computers via module: $($_.Exception.Message)"
}

if ($employees.Count -eq 0 -and $groups.Count -eq 0) {
    Write-Error "No directory objects retrieved. Ensure you are running as Domain Admin or account with AD read permissions."
    exit 1
}

$payload = @{
    kind = "directory"
    id = [guid]::NewGuid().ToString()
    data = @{
        complete = $true
        employees = $employees
        groups = $groups
        computers = $computers
    }
}

$body = @{
    schema_version = 2
    transport_id = [guid]::NewGuid().ToString()
    records = @($payload)
} | ConvertTo-Json -Depth 10 -Compress

$headers = @{
    "Authorization" = "Bearer $CollectorToken"
    "Content-Type" = "application/json"
}

try {
    $resp = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $body -TimeoutSec 15
    Write-Host "[+] Directory sync completed successfully! Synced $($employees.Count) users, $($groups.Count) groups, $($computers.Count) computers." -ForegroundColor Green
}
catch {
    Write-Error "[-] Directory sync ingest failed: $($_.Exception.Message)"
}
