<#
.SYNOPSIS
    AD Monitor - Windows VM Endpoint Monitoring Agent (v2.0)
.DESCRIPTION
    Runs inside authorized employee VMs (e.g. LAB-PC01).
    - Bounded 15-second read-only Process Monitor snapshots (working set, private bytes,
      CPU total processor time for delta calculation, owner SID/account, session ID,
      redacted command line, and cached Authenticode/SHA-256 verification).
    - Incremental Process Lifecycle harvesting (Security 4688/4689 and optional Sysmon 1/5)
      using -Oldest and durable checkpoints.
    - Separate 30-second device health, session, and USB presence heartbeats.
    - Durable bounded local retry queue with versioned transport_id ingestion contract.
#>

param (
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$AgentToken = "",
    [string]$TokenFile = "$PSScriptRoot\token.dpapi",
    [int]$ProcessIntervalSeconds = 15,
    [int]$HeartbeatIntervalSeconds = 30,
    [int]$MaxBatchProcesses = 200,
    [int]$MaxQueueFiles = 200,
    [string]$QueueDir = "$PSScriptRoot\agent_queue"
)

$ErrorActionPreference = "Continue"
$AgentVersion = "2.0.0"

if (-not (Test-Path $QueueDir)) {
    New-Item -ItemType Directory -Path $QueueDir -Force | Out-Null
}

# Load token from DPAPI file or environment if not passed directly
if (-not $AgentToken -and $env:ADMONITOR_AGENT_TOKEN) {
    $AgentToken = $env:ADMONITOR_AGENT_TOKEN
}
if (-not $AgentToken -and (Test-Path $TokenFile)) {
    try {
        $sec = Get-Content -Path $TokenFile -Raw | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        $AgentToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    } catch {
        Write-Warning "[-] Could not decrypt DPAPI token file at $TokenFile"
    }
}
if (-not $AgentToken) {
    Write-Error "AgentToken is required. Pass -AgentToken or store a DPAPI token at $TokenFile via install_agent.ps1."
    exit 1
}

# Persistent checkpoints file
$CheckpointPath = Join-Path $QueueDir "checkpoints.json"
$script:Checkpoints = @{
    security_lifecycle_record_id = [int64]0
    sysmon_lifecycle_record_id   = [int64]0
    ps_operational_record_id     = [int64]0
    security_failed_record_id    = [int64]0
}
if (Test-Path $CheckpointPath) {
    try {
        $loaded = Get-Content -Path $CheckpointPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($k in @($script:Checkpoints.Keys)) {
            if ($null -ne $loaded.$k) { $script:Checkpoints[$k] = [int64]$loaded.$k }
        }
    } catch {}
}

function Save-Checkpoints {
    try {
        ($script:Checkpoints | ConvertTo-Json -Compress) | Set-Content -Path $CheckpointPath -Encoding UTF8
    } catch {}
}

# Initialize checkpoints to current tail on first run so we do not replay months of old OS logs
function Initialize-TailCheckpoints {
    if ($script:Checkpoints.security_lifecycle_record_id -eq 0) {
        try {
            $ev = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4688 or EventID=4689)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($ev) { $script:Checkpoints.security_lifecycle_record_id = [int64]$ev.RecordId }
        } catch {}
    }
    if ($script:Checkpoints.sysmon_lifecycle_record_id -eq 0) {
        try {
            $ev = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1 or EventID=5)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($ev) { $script:Checkpoints.sysmon_lifecycle_record_id = [int64]$ev.RecordId }
        } catch {}
    }
    if ($script:Checkpoints.ps_operational_record_id -eq 0) {
        try {
            $ev = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($ev) { $script:Checkpoints.ps_operational_record_id = [int64]$ev.RecordId }
        } catch {}
    }
    if ($script:Checkpoints.security_failed_record_id -eq 0) {
        try {
            $ev = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4625 or EventID=4776 or EventID=4740)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($ev) { $script:Checkpoints.security_failed_record_id = [int64]$ev.RecordId }
        } catch {}
    }
    Save-Checkpoints
}

# Sensitive command-line redaction before transmission
function Format-RedactedCommandLine {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return $null }
    $redacted = $CmdLine
    $redacted = [regex]::Replace($redacted, '(?i)(-{1,2}(?:password|passwd|pwd|token|secret|api[-_]?key|authorization|bearer|client[-_]?secret|credential)\s*(?:=|\s+)\s*)(?:"[^"]*"|''[^'']*''|\S+)', '$1[REDACTED]')
    $redacted = [regex]::Replace($redacted, '(?i)((?:password|pwd|token|secret|api_key|apikey|access_token|refresh_token|SharedAccessSignature)=)([^&\s"''\x00]+)', '$1[REDACTED]')
    $redacted = [regex]::Replace($redacted, '(?i)(https?://[^/\s:@]+:)([^@\s/]+)(@)', '$1[REDACTED]$3')
    if ($redacted.Length -gt 2048) { $redacted = $redacted.Substring(0, 2048) }
    return $redacted
}

# Boot session ID and logical CPU count
$script:BootSessionId = "boot-unknown"
$script:LogicalCpuCount = [Math]::Max(1, [Environment]::ProcessorCount)
try {
    $osBoot = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osBoot -and $osBoot.LastBootUpTime) {
        $script:BootSessionId = "boot-" + $osBoot.LastBootUpTime.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    }
} catch {}

# File signature & SHA-256 cache keyed by path -> @{ ticks; length; sig_state; signer; sha256; hash_state }
$script:BinaryCache = @{}
# Owner cache keyed by "pid:creationTicks" -> @{ sid; account }
$script:OwnerCache = @{}

function Get-CachedBinaryMetadata {
    param(
        [string]$ExePath,
        [ref]$ChecksRemaining
    )
    if ([string]::IsNullOrWhiteSpace($ExePath)) {
        return @{ signature_state = "Unavailable"; signer = $null; sha256 = $null; hash_state = "Unavailable" }
    }
    try {
        if (-not (Test-Path -LiteralPath $ExePath)) {
            return @{ signature_state = "Unavailable"; signer = $null; sha256 = $null; hash_state = "Unavailable" }
        }
        $item = Get-Item -LiteralPath $ExePath -Force -ErrorAction Stop
        $ticks = $item.LastWriteTimeUtc.Ticks
        $len = $item.Length
        if ($script:BinaryCache.ContainsKey($ExePath)) {
            $cached = $script:BinaryCache[$ExePath]
            if ($cached.ticks -eq $ticks -and $cached.length -eq $len) {
                return $cached
            }
        }
        if ($ChecksRemaining.Value -le 0) {
            return @{ signature_state = "Not collected"; signer = $null; sha256 = $null; hash_state = "Not collected" }
        }
        $ChecksRemaining.Value = $ChecksRemaining.Value - 1

        $sigState = "Not collected"
        $signer = $null
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $ExePath -ErrorAction Stop
            if ($sig.Status -eq "Valid") {
                $sigState = "Verified"
                if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            } elseif ($sig.Status -eq "NotSigned") {
                $sigState = "Unsigned"
            } else {
                $sigState = "Invalid"
                if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            }
        } catch {
            $sigState = "Access denied"
        }

        $sha256 = $null
        $hashState = "Not collected"
        if ($len -gt 0 -and $len -le 52428800) {
            try {
                $h = Get-FileHash -LiteralPath $ExePath -Algorithm SHA256 -ErrorAction Stop
                $sha256 = $h.Hash.ToLower()
                $hashState = "Verified"
            } catch {
                $hashState = "Access denied"
            }
        }

        # Verify file did not change during hashing
        $itemAfter = Get-Item -LiteralPath $ExePath -Force -ErrorAction SilentlyContinue
        if ($itemAfter -and ($itemAfter.LastWriteTimeUtc.Ticks -ne $ticks -or $itemAfter.Length -ne $len)) {
            return @{ signature_state = "File changed"; signer = $null; sha256 = $null; hash_state = "File changed" }
        }

        $entry = @{
            ticks           = $ticks
            length          = $len
            signature_state = $sigState
            signer          = $signer
            sha256          = $sha256
            hash_state      = $hashState
        }
        if ($script:BinaryCache.Count -gt 1000) { $script:BinaryCache.Clear() }
        $script:BinaryCache[$ExePath] = $entry
        return $entry
    } catch [System.UnauthorizedAccessException] {
        return @{ signature_state = "Access denied"; signer = $null; sha256 = $null; hash_state = "Access denied" }
    } catch {
        return @{ signature_state = "Unavailable"; signer = $null; sha256 = $null; hash_state = "Unavailable" }
    }
}

function Get-ProcessSnapshotRecords {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $observedAt = [DateTime]::UtcNow.ToString("o")
    $snapshotId = "snap-" + [guid]::NewGuid().ToString()
    $errors = @()

    # Bulk WMI/CIM query for command line, parent PID, executable path, and creation date
    $cimByPid = @{}
    $cimObjByPid = @{}
    try {
        $cimProcs = Get-CimInstance Win32_Process -ErrorAction Stop
        foreach ($cp in $cimProcs) {
            $cimByPid[[int]$cp.ProcessId] = @{
                parent_pid      = [int]$cp.ParentProcessId
                executable_path = $cp.ExecutablePath
                command_line    = $cp.CommandLine
                creation_date   = $cp.CreationDate
                session_id      = [int]$cp.SessionId
                name            = $cp.Name
            }
            $cimObjByPid[[int]$cp.ProcessId] = $cp
        }
    } catch {
        $errors += "Win32_Process enumeration warning: $($_.Exception.Message)"
    }

    $liveProcs = @()
    try {
        $liveProcs = @(Get-Process -ErrorAction SilentlyContinue)
    } catch {
        $errors += "Get-Process warning: $($_.Exception.Message)"
    }

    $checksBudget = 15
    $ownerLookupsBudget = 60
    $procList = @()

    # Build a map of SessionId -> verified interactive user from explorer.exe or cached processes
    $sessionOwnerMap = @{}
    foreach ($ep in ($liveProcs | Where-Object { $_.ProcessName -eq "explorer" })) {
        $epPid = [int]$ep.Id
        if ($cimObjByPid.ContainsKey($epPid)) {
            try {
                $oRes = Invoke-CimMethod -InputObject $cimObjByPid[$epPid] -MethodName GetOwner -ErrorAction SilentlyContinue
                $sRes = Invoke-CimMethod -InputObject $cimObjByPid[$epPid] -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                $epAcct = if ($oRes -and $oRes.User) { if ($oRes.Domain) { "$($oRes.Domain)\$($oRes.User)" } else { $oRes.User } } else { $null }
                $epSid = if ($sRes -and $sRes.Sid) { $sRes.Sid } else { $null }
                if ($epSid -or $epAcct) {
                    $sessionOwnerMap[[int]$ep.SessionId] = @{ sid = $epSid; account = $epAcct }
                }
            } catch {}
        }
    }

    # Prioritize interactive session processes (SessionId > 0) before Session 0 services
    $orderedProcs = @($liveProcs | Sort-Object @{Expression = { if ($_.SessionId -gt 0) { 0 } else { 1 } }}, Id)

    foreach ($p in $orderedProcs) {
        try {
            $pidVal = [int]$p.Id
            $cimInfo = $cimByPid[$pidVal]
            $startIso = $null
            try {
                if ($p.StartTime) {
                    $startIso = $p.StartTime.ToUniversalTime().ToString("o")
                } elseif ($cimInfo -and $cimInfo.creation_date) {
                    $startIso = ([DateTime]$cimInfo.creation_date).ToUniversalTime().ToString("o")
                }
            } catch {}

            $exePath = $null
            try { $exePath = $p.Path } catch {}
            if (-not $exePath -and $cimInfo) { $exePath = $cimInfo.executable_path }

            $rawCmd = if ($cimInfo) { $cimInfo.command_line } else { $null }
            $cmdState = if ($null -ne $rawCmd -and $rawCmd -ne "") { "Collected" } elseif ($pidVal -in @(0, 4)) { "Unavailable" } else { "Access denied" }
            $redactedCmd = if ($cmdState -eq "Collected") { Format-RedactedCommandLine -CmdLine $rawCmd } else { $null }
            if ($redactedCmd -and $redactedCmd -like "*[REDACTED]*") { $cmdState = "Redacted" }

            $cpuMs = $null
            try {
                if ($null -ne $p.TotalProcessorTime) {
                    $cpuMs = [int64][Math]::Round($p.TotalProcessorTime.TotalMilliseconds)
                }
            } catch {}

            $wsBytes = $null
            $privBytes = $null
            try { $wsBytes = [int64]$p.WorkingSet64 } catch {}
            try { $privBytes = [int64]$p.PrivateMemorySize64 } catch {}

            $ownerCacheKey = "$pidVal`:$startIso"
            $userSid = $null
            $account = $null
            if ($script:OwnerCache.ContainsKey($ownerCacheKey)) {
                $userSid = $script:OwnerCache[$ownerCacheKey].sid
                $account = $script:OwnerCache[$ownerCacheKey].account
            } elseif ($pidVal -in @(0, 4)) {
                $script:OwnerCache[$ownerCacheKey] = @{ sid = $null; account = $null }
            } elseif ($ownerLookupsBudget -gt 0 -and $cimObjByPid.ContainsKey($pidVal)) {
                $ownerLookupsBudget--
                try {
                    $ownerRes = Invoke-CimMethod -InputObject $cimObjByPid[$pidVal] -MethodName GetOwner -ErrorAction SilentlyContinue
                    $sidRes = Invoke-CimMethod -InputObject $cimObjByPid[$pidVal] -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                    if ($ownerRes -and $ownerRes.User) {
                        $account = if ($ownerRes.Domain) { "$($ownerRes.Domain)\$($ownerRes.User)" } else { $ownerRes.User }
                    }
                    if ($sidRes -and $sidRes.Sid) {
                        $userSid = $sidRes.Sid
                    }
                    if ($script:OwnerCache.Count -gt 2000) { $script:OwnerCache.Clear() }
                    $script:OwnerCache[$ownerCacheKey] = @{ sid = $userSid; account = $account }
                } catch {
                    $script:OwnerCache[$ownerCacheKey] = @{ sid = $null; account = $null }
                }
            }
            if (((-not $userSid -and -not $account) -or ($account -like "*\Administrator")) -and ([int]$p.SessionId -gt 0) -and $sessionOwnerMap.ContainsKey([int]$p.SessionId)) {
                $userSid = $sessionOwnerMap[[int]$p.SessionId].sid
                $account = $sessionOwnerMap[[int]$p.SessionId].account
            }

            $binMeta = Get-CachedBinaryMetadata -ExePath $exePath -ChecksRemaining ([ref]$checksBudget)
            $pName = if ($p.ProcessName) { "$($p.ProcessName).exe" } elseif ($cimInfo -and $cimInfo.name) { $cimInfo.name } else { "PID-$pidVal" }
            if ($pName -like "*.exe.exe") { $pName = $pName.Substring(0, $pName.Length - 4) }

            $procList += @{
                pid                 = $pidVal
                name                = $pName
                creation_time       = $startIso
                parent_pid          = if ($cimInfo) { $cimInfo.parent_pid } else { $null }
                session_id          = [int]$p.SessionId
                executable_path     = $exePath
                command_line        = $redactedCmd
                command_line_state  = $cmdState
                user_sid            = $userSid
                account             = $account
                cpu_time_ms         = $cpuMs
                working_set_bytes   = $wsBytes
                private_bytes       = $privBytes
                signature_state     = $binMeta.signature_state
                signer              = $binMeta.signer
                sha256              = $binMeta.sha256
                hash_state          = $binMeta.hash_state
            }
        } catch {}
    }

    $sw.Stop()
    $totalCount = $procList.Count
    if ($totalCount -eq 0) {
        return @(@{
            id   = "$snapshotId-b1"
            kind = "process_snapshot"
            time = $observedAt
            data = @{
                snapshot_id        = $snapshotId
                boot_session_id    = $script:BootSessionId
                collector_version  = $AgentVersion
                sampled_at         = $observedAt
                observed_at        = $observedAt
                is_complete        = $false
                complete           = $false
                batch_index        = 1
                batch_total        = 1
                batch_count        = 1
                total_processes    = 0
                logical_cpus       = $script:LogicalCpuCount
                sample_duration_ms = [int]$sw.ElapsedMilliseconds
                duration_ms        = [int]$sw.ElapsedMilliseconds
                errors             = $errors + @("No processes returned from enumeration")
                processes          = @()
            }
        })
    }

    # Split into coherent batches if process list exceeds $MaxBatchProcesses
    $batchCount = [int][Math]::Ceiling($totalCount / [double]$MaxBatchProcesses)
    $records = @()
    for ($i = 0; $i -lt $batchCount; $i++) {
        $bIdx = $i + 1
        $slice = @($procList | Select-Object -Skip ($i * $MaxBatchProcesses) -First $MaxBatchProcesses)
        $records += @{
            id   = "$snapshotId-b$bIdx"
            kind = "process_snapshot"
            time = $observedAt
            data = @{
                snapshot_id        = $snapshotId
                boot_session_id    = $script:BootSessionId
                collector_version  = $AgentVersion
                sampled_at         = $observedAt
                observed_at        = $observedAt
                is_complete        = ($errors.Count -eq 0 -and $bIdx -eq $batchCount)
                complete           = ($errors.Count -eq 0 -and $bIdx -eq $batchCount)
                batch_index        = $bIdx
                batch_total        = $batchCount
                batch_count        = $batchCount
                total_processes    = $totalCount
                logical_cpus       = $script:LogicalCpuCount
                sample_duration_ms = [int]$sw.ElapsedMilliseconds
                duration_ms        = [int]$sw.ElapsedMilliseconds
                errors             = $errors
                processes          = $slice
            }
        }
    }
    return $records
}

function Get-ProcessLifecycleRecords {
    $recs = @()
    # 1. Windows Security 4688 (Process Creation) and 4689 (Process Termination)
    try {
        $lastSec = $script:Checkpoints.security_lifecycle_record_id
        $xpath = "*[System[((EventID=4688 or EventID=4689) and (EventRecordID > $lastSec))]]"
        $evs = @(Get-WinEvent -LogName "Security" -FilterXPath $xpath -MaxEvents 40 -Oldest -ErrorAction SilentlyContinue)
        foreach ($ev in $evs) {
            $recs += @{
                kind        = "windows"
                id          = "sec_proc_$($ev.RecordId)"
                xml         = $ev.ToXml()
                _ckpt_field = "security_lifecycle_record_id"
                _ckpt_val   = [int64]$ev.RecordId
            }
        }
    } catch {}

    # 2. Optional Sysmon Event ID 1 (Process Create) and 5 (Process Terminated) if Sysmon is installed
    try {
        $lastSys = $script:Checkpoints.sysmon_lifecycle_record_id
        $xpathSys = "*[System[((EventID=1 or EventID=5) and (EventRecordID > $lastSys))]]"
        $sysEvs = @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $xpathSys -MaxEvents 40 -Oldest -ErrorAction SilentlyContinue)
        foreach ($ev in $sysEvs) {
            $recs += @{
                kind        = "windows"
                id          = "sysmon_proc_$($ev.RecordId)"
                xml         = $ev.ToXml()
                _ckpt_field = "sysmon_lifecycle_record_id"
                _ckpt_val   = [int64]$ev.RecordId
            }
        }
    } catch {}
    return $recs
}

function Get-SystemMetrics {
    $cpu = 0.0
    try {
        $cpuSamples = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
        if ($cpuSamples) { $cpu = [double]$cpuSamples.PercentProcessorTime }
    } catch {}

    $osInfo = Get-CimInstance Win32_OperatingSystem
    $totalRamKb = [double]$osInfo.TotalVisibleMemorySize
    $freeRamKb = [double]$osInfo.FreePhysicalMemory
    $usedRamKb = $totalRamKb - $freeRamKb
    $ramPercent = [math]::Round(($usedRamKb / [math]::Max($totalRamKb, 1.0)) * 100.0, 1)

    $disks = @()
    $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    foreach ($d in $logicalDisks) {
        $sizeBytes = [int64]$d.Size
        $freeBytes = [int64]$d.FreeSpace
        $usedBytes = $sizeBytes - $freeBytes
        $pct = if ($sizeBytes -gt 0) { [math]::Round(($usedBytes / $sizeBytes) * 100.0, 1) } else { 0.0 }
        $disks += @{
            device_id   = $d.DeviceID
            total_bytes = $sizeBytes
            free_bytes  = $freeBytes
            used_bytes  = $usedBytes
            percent     = $pct
        }
    }

    return @{
        cpu           = [math]::Round($cpu, 1)
        ram_percent   = $ramPercent
        ram_used      = [int64]($usedRamKb * 1024)
        ram_available = [int64]($freeRamKb * 1024)
        ram_total     = [int64]($totalRamKb * 1024)
        disks         = $disks
    }
}

function Get-UserSessions {
    $sessions = @()
    try {
        $loggedOn = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Select-Object -Unique Antecedent
        foreach ($item in $loggedOn) {
            if ($item.Antecedent.Name -and $item.Antecedent.Name -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-") {
                $sessions += @{
                    id      = "$($item.Antecedent.Domain)\$($item.Antecedent.Name)"
                    account = "$($item.Antecedent.Domain)\$($item.Antecedent.Name)"
                    state   = "Active"
                }
            }
        }
    } catch {}
    return $sessions
}

$script:KnownUsbIds = @{}

function Get-UsbEvents {
    $events = @()
    try {
        $currentMap = @{}
        $currentUsb = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceType -eq 'USB' -or $_.MediaType -like '*Removable*' -or $_.PNPDeviceID -like 'USB*'
        })
        foreach ($dev in $currentUsb) {
            $id = [string]$dev.DeviceID
            $model = if ($dev.Model) { [string]$dev.Model } else { "USB Storage Device ($id)" }
            $currentMap[$id] = @{ model = $model; size = $dev.Size; partitions = $dev.Partitions }
        }
        $remLogical = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue)
        foreach ($ld in $remLogical) {
            $lid = "USB Removable Drive ($($ld.DeviceID))"
            $vname = if ($ld.VolumeName) { "$($ld.VolumeName) ($($ld.DeviceID))" } else { "Removable Disk ($($ld.DeviceID))" }
            if (-not $currentMap.ContainsKey($lid)) {
                $currentMap[$lid] = @{ model = $vname; size = $ld.Size; partitions = 1 }
            }
        }
        foreach ($idKey in $currentMap.Keys) {
            if (-not $script:KnownUsbIds.ContainsKey($idKey)) {
                $meta = $currentMap[$idKey]
                $events += @{
                    id         = [guid]::NewGuid().ToString()
                    time       = [DateTime]::UtcNow.ToString("o")
                    action     = "connected"
                    identifier = $idKey
                    metadata   = $meta
                }
            }
        }
        foreach ($oldKey in $script:KnownUsbIds.Keys) {
            if (-not $currentMap.ContainsKey($oldKey)) {
                $events += @{
                    id         = [guid]::NewGuid().ToString()
                    time       = [DateTime]::UtcNow.ToString("o")
                    action     = "disconnected"
                    identifier = $oldKey
                    metadata   = $script:KnownUsbIds[$oldKey]
                }
            }
        }
        $script:KnownUsbIds = $currentMap
    } catch {}
    return $events
}

$script:KnownUsbFiles = @{}
$script:UsbInitialScanDone = $false
function Get-RealUsbFileTransfers {
    $obs = @()
    try {
        $removables = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
            $_.DriveType -eq 2 -or ($_.DriveType -eq 3 -and $_.DeviceID -ne 'C:')
        })
        foreach ($drv in $removables) {
            $letter = $drv.DeviceID
            $files = Get-ChildItem -Path "$letter\" -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $key = "$($f.FullName)_$($f.Length)_$($f.LastWriteTimeUtc.Ticks)"
                if (-not $script:KnownUsbFiles.ContainsKey($key)) {
                    $script:KnownUsbFiles[$key] = $true
                    $isRecent = ($f.LastWriteTimeUtc -ge ([DateTime]::UtcNow.AddMinutes(-10))) -or ($f.CreationTimeUtc -ge ([DateTime]::UtcNow.AddMinutes(-10)))
                    if ($script:UsbInitialScanDone -or $isRecent) {
                        $obs += @{
                            id   = [guid]::NewGuid().ToString()
                            kind = "observation"
                            time = [DateTime]::UtcNow.ToString("o")
                            data = @{
                                category              = "file_copy"
                                source_path           = $f.Name
                                destination_path      = $f.FullName
                                destination_removable = $true
                                bytes                 = [int64]$f.Length
                                hostname              = $env:COMPUTERNAME
                                account               = "$env:USERDOMAIN\$env:USERNAME"
                            }
                        }
                    }
                }
            }
        }
        $script:UsbInitialScanDone = $true
    } catch {}
    return $obs
}

function Get-RealPowerShellLogs {
    $obs = @()
    try {
        $lastId = $script:Checkpoints.ps_operational_record_id
        $xpath = "*[System[(EventID=4104 and EventRecordID > $lastId)]]"
        $evs = @(Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath $xpath -MaxEvents 25 -Oldest -ErrorAction SilentlyContinue)
        foreach ($ev in $evs) {
            $txt = $ev.Properties[2].Value.ToString()
            $lower = $txt.ToLower()
            $suspicious = @('-enc', 'encodedcommand', 'frombase64string', 'downloadstring', 'invoke-expression', 'iex', 'net.webclient', 'bypass', 'mimikatz', 'sekurlsa', 'whoami /priv')
            $matched = @()
            foreach ($s in $suspicious) { if ($lower.Contains($s)) { $matched += $s } }
            if ($matched.Count -gt 0) {
                $obs += @{
                    id          = "ps4104_$($ev.RecordId)"
                    kind        = "observation"
                    time        = $ev.TimeCreated.ToUniversalTime().ToString("o")
                    _ckpt_field = "ps_operational_record_id"
                    _ckpt_val   = [int64]$ev.RecordId
                    data        = @{
                        category           = "script_block"
                        command_line       = (Format-RedactedCommandLine -CmdLine $txt.Substring(0, [math]::Min(500, $txt.Length)))
                        ScriptBlockText    = (Format-RedactedCommandLine -CmdLine $txt.Substring(0, [math]::Min(2000, $txt.Length)))
                        heuristics_matched = $matched
                        hostname           = $env:COMPUTERNAME
                        account            = "$env:USERDOMAIN\$env:USERNAME"
                    }
                }
            } else {
                $script:Checkpoints.ps_operational_record_id = [int64]$ev.RecordId
            }
        }
    } catch {}
    return $obs
}

function Get-RealFailedLogonEvents {
    $recs = @()
    try {
        $lastId = $script:Checkpoints.security_failed_record_id
        $filter = "*[System[((EventID=4625 or EventID=4776 or EventID=4740) and (EventRecordID > $lastId))]]"
        $evs = @(Get-WinEvent -LogName "Security" -FilterXPath $filter -MaxEvents 25 -Oldest -ErrorAction SilentlyContinue)
        foreach ($ev in $evs) {
            $recs += @{
                kind        = "windows"
                id          = "sec_fail_$($ev.RecordId)"
                xml         = $ev.ToXml()
                _ckpt_field = "security_failed_record_id"
                _ckpt_val   = [int64]$ev.RecordId
            }
        }
    } catch {}
    return $recs
}

$script:DroppedBatches = 0

function Send-OrQueueBatch {
    param([array]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return $true }

    # Strip internal checkpoint tracking keys before serializing
    $cleanRecords = @()
    $pendingCheckpoints = @{}
    foreach ($r in $Records) {
        $copy = @{}
        foreach ($k in $r.Keys) {
            if ($k -notlike "_ckpt_*") { $copy[$k] = $r[$k] }
        }
        $cleanRecords += $copy
        if ($r._ckpt_field -and $r._ckpt_val) {
            $pendingCheckpoints[$r._ckpt_field] = [int64]$r._ckpt_val
        }
    }

    $transportId = [guid]::NewGuid().ToString()
    $ckptStrings = @{}
    foreach ($k in $pendingCheckpoints.Keys) { $ckptStrings[$k] = "$($pendingCheckpoints[$k])" }

    $payloadObj = @{
        schema_version = 2
        transport_id   = $transportId
        records        = $cleanRecords
        checkpoints    = $ckptStrings
        diagnostics    = @{
            agent_version   = $AgentVersion
            boot_session_id = $script:BootSessionId
            dropped_batches = $script:DroppedBatches
        }
    }
    $body = $payloadObj | ConvertTo-Json -Depth 8 -Compress

    $headers = @{
        "Authorization" = "Bearer $AgentToken"
        "Content-Type"  = "application/json"
    }

    try {
        $resp = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $body -TimeoutSec 12
        foreach ($k in $pendingCheckpoints.Keys) {
            if ($pendingCheckpoints[$k] -gt $script:Checkpoints[$k]) {
                $script:Checkpoints[$k] = $pendingCheckpoints[$k]
            }
        }
        Save-Checkpoints
        return $true
    } catch {
        Write-Warning "[$([DateTime]::Now.ToString('T'))] [-] Delivery failed ($($_.Exception.Message)); spooling batch $transportId to durable queue."
        try {
            $existing = @(Get-ChildItem -Path $QueueDir -Filter "batch_*.json" | Sort-Object CreationTime)
            if ($existing.Count -ge $MaxQueueFiles) {
                Remove-Item -Path $existing[0].FullName -Force -ErrorAction SilentlyContinue
                $script:DroppedBatches++
            }
            $qFile = Join-Path $QueueDir "batch_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())_$transportId.json"
            $body | Set-Content -Path $qFile -Encoding UTF8
            foreach ($k in $pendingCheckpoints.Keys) {
                if ($pendingCheckpoints[$k] -gt $script:Checkpoints[$k]) {
                    $script:Checkpoints[$k] = $pendingCheckpoints[$k]
                }
            }
            Save-Checkpoints
        } catch {}
        return $false
    }
}

function Flush-QueuedBatches {
    $queued = @(Get-ChildItem -Path $QueueDir -Filter "batch_*.json" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 10)
    foreach ($qf in $queued) {
        try {
            $raw = Get-Content -Path $qf.FullName -Raw -Encoding UTF8
            $headers = @{
                "Authorization" = "Bearer $AgentToken"
                "Content-Type"  = "application/json"
            }
            Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $raw -TimeoutSec 12 | Out-Null
            Remove-Item -Path $qf.FullName -Force
            Write-Host "[+] Flushed queued batch $($qf.Name)" -ForegroundColor DarkGreen
        } catch {
            break
        }
    }
}

Initialize-TailCheckpoints

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - Endpoint Agent v$AgentVersion" -ForegroundColor Cyan
Write-Host " Target Machine:   $env:COMPUTERNAME ($script:BootSessionId)" -ForegroundColor Cyan
Write-Host " Backend URL:      $BackendUrl" -ForegroundColor Cyan
Write-Host " Process Snapshot: Every $ProcessIntervalSeconds seconds (Read-Only)" -ForegroundColor Green
Write-Host " Heartbeat:        Every $HeartbeatIntervalSeconds seconds" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$lastHeartbeatAt = [DateTime]::MinValue

while ($true) {
    Flush-QueuedBatches

    $batchRecords = @()

    # 1. Always collect 15-second Process Snapshot + Process Lifecycle events
    $snapRecords = Get-ProcessSnapshotRecords
    if ($snapRecords) { $batchRecords += $snapRecords }

    $lcRecords = Get-ProcessLifecycleRecords
    if ($lcRecords) { $batchRecords += $lcRecords }

    # 2. Separate 30-second device health / USB / session heartbeat
    $nowUtc = [DateTime]::UtcNow
    if (($nowUtc - $lastHeartbeatAt).TotalSeconds -ge $HeartbeatIntervalSeconds) {
        $lastHeartbeatAt = $nowUtc
        $nowIso = $nowUtc.ToString("o")
        $metrics = Get-SystemMetrics
        $sessions = Get-UserSessions
        $usb = Get-UsbEvents

        $ips = @()
        try {
            $ipAddrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" }
            foreach ($a in $ipAddrs) { $ips += $a.IPAddress }
        } catch {}

        $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
        $batchRecords += @{
            kind = "heartbeat"
            id   = "hb-" + [guid]::NewGuid().ToString()
            data = @{
                hostname      = $env:COMPUTERNAME
                time          = $nowIso
                os            = $osCaption
                ips           = $ips
                agent_version = $AgentVersion
                health        = $metrics
                sessions      = $sessions
                usb_events    = $usb
                errors        = @()
            }
        }
    }

    $usbFiles = Get-RealUsbFileTransfers
    $psLogs = Get-RealPowerShellLogs
    $failedLogons = Get-RealFailedLogonEvents
    if ($usbFiles) { $batchRecords += $usbFiles }
    if ($psLogs) { $batchRecords += $psLogs }
    if ($failedLogons) { $batchRecords += $failedLogons }

    $ok = Send-OrQueueBatch -Records $batchRecords
    if ($ok) {
        Write-Host "[$([DateTime]::Now.ToString('T'))] [+] Delivered $($batchRecords.Count) record(s) (Process snapshot + telemetry)" -ForegroundColor Green
    }

    Start-Sleep -Seconds $ProcessIntervalSeconds
}
