param([string]$SearchBase)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module ActiveDirectory
$opts = @{}
if ($SearchBase) { $opts.SearchBase = $SearchBase }
$domain = (Get-ADDomain).NetBIOSName
$allGroups = @(Get-ADGroup -Filter * @opts)
$map = @{}
foreach ($g in $allGroups) { $map[$g.DistinguishedName] = $g.SID.Value }
$employees = @(Get-ADUser -Filter * -Properties Department,DisplayName,MemberOf @opts | ForEach-Object {
    $membership = @($_.MemberOf | ForEach-Object { if ($map.ContainsKey($_)) { $map[$_] } })
    @{sid=$_.SID.Value; account="$domain\$($_.SamAccountName)"; name=$_.DisplayName; department=$_.Department; enabled=$_.Enabled; group_sids=$membership}
})
$groups = @($allGroups | ForEach-Object { @{sid=$_.SID.Value; name=$_.Name} })
$computers = @(Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem @opts | ForEach-Object { @{sid=$_.SID.Value; hostname=$(if ($_.DNSHostName) {$_.DNSHostName} else {$_.Name}); os=$_.OperatingSystem} })
@{complete=$true;employees=$employees;groups=$groups;computers=$computers;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 10 -Compress
