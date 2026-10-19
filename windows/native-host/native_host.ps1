#requires -Version 5.1
<#
.SYNOPSIS
    AD Monitor - Pure PowerShell Windows Native Messaging Host (com.admonitor.browser_bridge)
    Zero external dependencies required on Windows endpoints (LAB-PC01).
#>
param(
    [Parameter(Position=0)][string]$CallerOrigin = "",
    [Parameter(ValueFromRemainingArguments=$true)]$RemainingArgs
)

$ErrorActionPreference = "Stop"
$MaxMessageBytes = 262144
$MaxHashFileBytes = 104857600
$MaxSpoolRecords = 1000

function Get-UtcNowIso {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-BridgeAppDir {
    if ($env:ADMONITOR_NATIVE_HOST_DIR) {
        $dir = $env:ADMONITOR_NATIVE_HOST_DIR
    } elseif (Test-Path -LiteralPath (Join-Path $PSScriptRoot "config.json")) {
        $dir = $PSScriptRoot
    } elseif (Test-Path -LiteralPath "C:\ADMonitor\BrowserBridge\config.json") {
        $dir = "C:\ADMonitor\BrowserBridge"
    } else {
        $dir = Join-Path $env:LOCALAPPDATA "ADMonitor\BrowserBridge"
    }
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Get-UserSpoolDir {
    if ($env:ADMONITOR_NATIVE_HOST_DIR) {
        return $env:ADMONITOR_NATIVE_HOST_DIR
    }
    $dir = Join-Path $env:LOCALAPPDATA "ADMonitor\BrowserBridge"
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Get-BridgeConfig {
    $appDir = Get-BridgeAppDir
    $cfgPath = Join-Path $appDir "config.json"
    $cfg = @{
        backend_url = "http://192.168.77.1:8765"
        device_hostname = $env:COMPUTERNAME
        token_file = (Join-Path $appDir "token.dpapi")
        machine_token_file = (Join-Path $appDir "token.machine.dpapi")
        machine_key_file = (Join-Path $appDir "machine.key")
        allowed_origins = @()
        enrolled_profiles = @{}
        last_delivery_at = $null
    }
    if (Test-Path -LiteralPath $cfgPath) {
        try {
            $loaded = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($loaded.backend_url) { $cfg.backend_url = [string]$loaded.backend_url }
            if ($loaded.device_hostname) { $cfg.device_hostname = [string]$loaded.device_hostname }
            if ($loaded.token_file) { $cfg.token_file = [string]$loaded.token_file }
            if ($loaded.machine_token_file) { $cfg.machine_token_file = [string]$loaded.machine_token_file }
            if ($loaded.machine_key_file) { $cfg.machine_key_file = [string]$loaded.machine_key_file }
            if ($loaded.allowed_origins) { $cfg.allowed_origins = @($loaded.allowed_origins) }
            if ($loaded.last_delivery_at) { $cfg.last_delivery_at = [string]$loaded.last_delivery_at }
            if ($loaded.enrolled_profiles) {
                $ep = @{}
                foreach ($prop in $loaded.enrolled_profiles.PSObject.Properties) {
                    $ep[$prop.Name] = $prop.Value
                }
                $cfg.enrolled_profiles = $ep
            }
        } catch {}
    }
    return $cfg
}

function Save-BridgeConfig($cfg) {
    $appDir = Get-BridgeAppDir
    $cfgPath = Join-Path $appDir "config.json"
    try {
        $cfg | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cfgPath -Encoding UTF8
    } catch {}
}

function ConvertFrom-SecureStringPlain($sec) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-CollectorToken($cfg) {
    if ($env:ADMONITOR_BROWSER_TOKEN) {
        return $env:ADMONITOR_BROWSER_TOKEN.Trim()
    }
    $tokFile = $cfg.token_file
    if ($tokFile -and (Test-Path -LiteralPath $tokFile)) {
        try {
            $raw = (Get-Content -LiteralPath $tokFile -Raw -Encoding UTF8).Trim()
            if ($raw) {
                $sec = ConvertTo-SecureString $raw -ErrorAction Stop
                $plain = ConvertFrom-SecureStringPlain $sec
                if ($plain) { return $plain }
            }
        } catch {}
    }
    $mTokFile = $cfg.machine_token_file
    $mKeyFile = $cfg.machine_key_file
    if ($mTokFile -and $mKeyFile -and (Test-Path -LiteralPath $mTokFile) -and (Test-Path -LiteralPath $mKeyFile)) {
        try {
            $raw = (Get-Content -LiteralPath $mTokFile -Raw -Encoding UTF8).Trim()
            $keyB64 = (Get-Content -LiteralPath $mKeyFile -Raw -Encoding UTF8).Trim()
            if ($raw -and $keyB64) {
                $keyBytes = [Convert]::FromBase64String($keyB64)
                $sec = ConvertTo-SecureString $raw -Key $keyBytes -ErrorAction Stop
                $plain = ConvertFrom-SecureStringPlain $sec
                if ($plain) { return $plain }
            }
        } catch {}
    }
    return $null
}

function Get-OsIdentity {
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $osUser = $wi.Name
    $osSid = if ($wi.User) { $wi.User.Value } else { "S-1-5-21-UNKNOWN" }
    if ($osUser -like "*\Administrator" -or $osSid -eq "S-1-5-18") {
        try {
            $expCim = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($expCim) {
                $oRes = Invoke-CimMethod -InputObject $expCim -MethodName GetOwner -ErrorAction SilentlyContinue
                $sRes = Invoke-CimMethod -InputObject $expCim -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                if ($oRes -and $oRes.User -and $sRes -and $sRes.Sid) {
                    $osUser = if ($oRes.Domain) { "$($oRes.Domain)\$($oRes.User)" } else { $oRes.User }
                    $osSid = $sRes.Sid
                }
            }
        } catch {}
    }
    return @{
        os_user = $osUser
        os_sid = $osSid
        device_hostname = $env:COMPUTERNAME
    }
}

function Get-SafeDownloadHash([string]$targetPath) {
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        return @{ sha256 = $null; exists = $null }
    }
    try {
        if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            return @{ sha256 = $null; exists = $false }
        }
        $item = Get-Item -LiteralPath $targetPath -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            return @{ sha256 = $null; exists = $false }
        }
        $fullPath = $item.FullName
        $homeFull = [System.IO.Path]::GetFullPath($HOME)
        if (-not ($fullPath.StartsWith($homeFull, [System.StringComparison]::OrdinalIgnoreCase) -or $fullPath.StartsWith("C:\Users\", [System.StringComparison]::OrdinalIgnoreCase))) {
            return @{ sha256 = $null; exists = $true }
        }
        if ($item.Length -gt $MaxHashFileBytes) {
            return @{ sha256 = $null; exists = $true }
        }
        $hashObj = Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 -ErrorAction Stop
        return @{ sha256 = $hashObj.Hash.ToLowerInvariant(); exists = $true }
    } catch {
        return @{ sha256 = $null; exists = $null }
    }
}

function Get-SpoolList {
    $list = New-Object System.Collections.ArrayList
    $spoolFile = Join-Path (Get-UserSpoolDir) "spool.json"
    if (Test-Path -LiteralPath $spoolFile) {
        try {
            $raw = Get-Content -LiteralPath $spoolFile -Raw -Encoding UTF8
            if ($raw) {
                $parsed = ConvertFrom-Json $raw
                if ($parsed -is [System.Array]) {
                    foreach ($item in $parsed) { [void]$list.Add($item) }
                } elseif ($null -ne $parsed) {
                    [void]$list.Add($parsed)
                }
            }
        } catch {}
    }
    return ,$list
}

function Save-SpoolList($list) {
    $spoolFile = Join-Path (Get-UserSpoolDir) "spool.json"
    if ($null -eq $list -or $list.Count -eq 0) {
        "[]" | Set-Content -LiteralPath $spoolFile -Encoding UTF8
        return
    }
    while ($list.Count -gt $MaxSpoolRecords) {
        $list.RemoveAt(0)
    }
    ConvertTo-Json -InputObject @($list) -Depth 10 -Compress | Set-Content -LiteralPath $spoolFile -Encoding UTF8
}

function Add-SpoolRecords($records) {
    $list = Get-SpoolList
    $existingIds = @{}
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i].id) { $existingIds[[string]$list[$i].id] = $i }
    }
    foreach ($r in $records) {
        $rid = [string]$r.id
        if ($existingIds.ContainsKey($rid)) {
            $list[$existingIds[$rid]] = $r
        } else {
            [void]$list.Add($r)
        }
    }
    Save-SpoolList $list
    return $list.Count
}

function ConvertTo-HashtableRecursive($obj) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $obj.Keys) { $h[$k] = ConvertTo-HashtableRecursive $obj[$k] }
        return $h
    }
    if ($obj -is [PSCustomObject]) {
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-HashtableRecursive $p.Value }
        return $h
    }
    if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
        $arr = @()
        foreach ($item in $obj) { $arr += ,(ConvertTo-HashtableRecursive $item) }
        return $arr
    }
    return $obj
}

function Format-EnrichedRecord($recObj, $identity, $cfg, [string]$caller) {
    $rec = ConvertTo-HashtableRecursive $recObj
    $recId = if ($rec.id) { [string]$rec.id } else { "brec-" + [guid]::NewGuid().ToString() }
    $kind = [string]$rec.kind
    $data = if ($rec.data) { ConvertTo-HashtableRecursive $rec.data } else { @{} }

    $data["windows_user"] = $identity.os_user
    $data["account"] = $identity.os_user
    $data["windows_sid"] = $identity.os_sid
    $data["user_sid"] = $identity.os_sid
    $data["device_hostname"] = if ($cfg.device_hostname) { $cfg.device_hostname } else { $identity.device_hostname }

    if (-not $data["extension_id"]) {
        $extFromOrigin = ""
        if ($caller -and $caller.Contains("://")) {
            $extFromOrigin = $caller.Split(@("://"), [System.StringSplitOptions]::None)[1].Trim("/ ")
        }
        $data["extension_id"] = if ($extFromOrigin) { $extFromOrigin } else { "fjjbkbkbogknhemdmopognpnbabmfbog" }
    }

    if ($kind -eq "browser_download") {
        $st = ([string]$data["state"]).ToLowerInvariant()
        if ($st -eq "complete" -or $st -eq "completed") {
            $data["state"] = "completed"
            $pToHash = if ($data["final_path"]) { [string]$data["final_path"] } else { [string]$data["target_path"] }
            $hashRes = Get-SafeDownloadHash $pToHash
            if ($hashRes.sha256 -and -not $data["sha256"]) {
                $data["sha256"] = $hashRes.sha256
                $data["hash_state"] = "Verified"
            }
            if ($null -ne $hashRes.exists) {
                $data["file_exists"] = [bool]$hashRes.exists
                $data["exists_on_disk"] = [bool]$hashRes.exists
            }
        }
    }

    return @{
        id = $recId
        kind = $kind
        data = $data
    }
}

function Send-SpoolBatch($cfg) {
    $list = Get-SpoolList
    if ($list.Count -eq 0) {
        return @{ ok = $true; ack = @(); depth = 0; error = $null }
    }
    $token = Get-CollectorToken $cfg
    if (-not $token) {
        return @{ ok = $false; ack = @(); depth = $list.Count; error = "Collector token not configured in Native Host" }
    }
    $batchCount = [Math]::Min(50, $list.Count)
    $batch = @()
    for ($i = 0; $i -lt $batchCount; $i++) { $batch += ,$list[$i] }

    $backendUrl = ([string]$cfg.backend_url).TrimEnd('/')
    $payload = @{
        schema_version = 2
        transport_id = [guid]::NewGuid().ToString()
        records = $batch
    }
    $jsonBody = $payload | ConvertTo-Json -Depth 10 -Compress
    try {
        $headers = @{ Authorization = "Bearer $token" }
        $resp = Invoke-RestMethod -Uri "$backendUrl/api/ingest" -Method Post -Headers $headers -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -TimeoutSec 10
        $doneSet = @{}
        if ($resp.acknowledged) { foreach ($id in $resp.acknowledged) { $doneSet[[string]$id] = $true } }
        if ($resp.accepted) { foreach ($id in $resp.accepted) { $doneSet[[string]$id] = $true } }
        if ($resp.duplicates) { foreach ($id in $resp.duplicates) { $doneSet[[string]$id] = $true } }

        $remaining = [System.Collections.ArrayList]@()
        foreach ($item in $list) {
            if (-not $doneSet.ContainsKey([string]$item.id)) {
                [void]$remaining.Add($item)
            }
        }
        Save-SpoolList $remaining
        return @{ ok = $true; ack = @($doneSet.Keys); depth = $remaining.Count; error = $null }
    } catch {
        return @{ ok = $false; ack = @(); depth = $list.Count; error = $_.Exception.Message }
    }
}

function Invoke-NativeMessage($msgObj, [string]$caller) {
    $cfg = Get-BridgeConfig
    if ($cfg.allowed_origins -and $cfg.allowed_origins.Count -gt 0 -and $caller) {
        $normCaller = $caller.TrimEnd('/').ToLowerInvariant()
        $allowed = $false
        foreach ($o in $cfg.allowed_origins) {
            if (([string]$o).TrimEnd('/').ToLowerInvariant() -eq $normCaller) {
                $allowed = $true
                break
            }
        }
        if (-not $allowed) {
            return @{ ok = $false; error = "Extension origin $caller is not in allowed_origins" }
        }
    }

    $identity = Get-OsIdentity
    $action = if ($msgObj.action) { [string]$msgObj.action } else { "status" }
    $profileId = if ($msgObj.profile_id) { [string]$msgObj.profile_id } else { "" }

    if ($action -eq "status") {
        $spool = Get-SpoolList
        $isEnrolled = [bool]($profileId -and $cfg.enrolled_profiles.ContainsKey($profileId))
        return @{
            ok = $true
            enrolled = $isEnrolled
            os_user = $identity.os_user
            os_sid = $identity.os_sid
            device_hostname = $cfg.device_hostname
            queue_depth = $spool.Count
            delivered_at = $cfg.last_delivery_at
        }
    }

    if ($action -eq "enroll") {
        if (-not $profileId) {
            return @{ ok = $false; error = "Missing profile_id" }
        }
        $shortGuid = [guid]::NewGuid().ToString("N").Substring(0, 8)
        $rawRec = @{
            id = "benroll-$profileId-$shortGuid"
            kind = "browser_enrollment"
            data = @{
                profile_id = $profileId
                profile_label = if ($msgObj.profile_label) { [string]$msgObj.profile_label } else { "Work Browser Profile" }
                browser_name = if ($msgObj.browser_name) { [string]$msgObj.browser_name } else { "Microsoft Edge" }
                browser_version = if ($msgObj.browser_version) { [string]$msgObj.browser_version } else { "unknown" }
                extension_id = $msgObj.extension_id
                extension_version = if ($msgObj.extension_version) { [string]$msgObj.extension_version } else { "2.0.0" }
                status = "active"
                enrolled_at = Get-UtcNowIso
            }
        }
        $enriched = Format-EnrichedRecord $rawRec $identity $cfg $caller
        [void](Add-SpoolRecords @($enriched))
        $fwd = Send-SpoolBatch $cfg
        $cfg.enrolled_profiles[$profileId] = @{
            profile_label = $enriched.data["profile_label"]
            enrolled_at = Get-UtcNowIso
            os_user = $identity.os_user
            os_sid = $identity.os_sid
        }
        if ($fwd.ok) { $cfg.last_delivery_at = Get-UtcNowIso }
        Save-BridgeConfig $cfg
        return @{
            ok = [bool]$fwd.ok
            enrolled = $true
            os_user = $identity.os_user
            os_sid = $identity.os_sid
            device_hostname = $cfg.device_hostname
            queue_depth = $fwd.depth
            delivered_at = $cfg.last_delivery_at
            error = $fwd.error
        }
    }

    if ($action -eq "heartbeat") {
        $shortGuid = [guid]::NewGuid().ToString("N").Substring(0, 8)
        $isPaused = [bool]$msgObj.paused
        $rawRec = @{
            id = "bhb-$profileId-$shortGuid"
            kind = "browser_status"
            data = @{
                profile_id = $profileId
                browser_name = if ($msgObj.browser_name) { [string]$msgObj.browser_name } else { "Microsoft Edge" }
                browser_version = if ($msgObj.browser_version) { [string]$msgObj.browser_version } else { "unknown" }
                extension_id = $msgObj.extension_id
                extension_version = if ($msgObj.extension_version) { [string]$msgObj.extension_version } else { "2.0.0" }
                state = if ($isPaused) { "Paused" } else { "Enrolled" }
                status = if ($isPaused) { "paused" } else { "active" }
                reason = "Periodic heartbeat"
                observed_at = Get-UtcNowIso
            }
        }
        $enriched = Format-EnrichedRecord $rawRec $identity $cfg $caller
        [void](Add-SpoolRecords @($enriched))
        $fwd = Send-SpoolBatch $cfg
        if ($fwd.ok) {
            $cfg.last_delivery_at = Get-UtcNowIso
            Save-BridgeConfig $cfg
        }
        return @{
            ok = [bool]$fwd.ok
            os_user = $identity.os_user
            os_sid = $identity.os_sid
            device_hostname = $cfg.device_hostname
            queue_depth = $fwd.depth
            delivered_at = $cfg.last_delivery_at
            error = $fwd.error
        }
    }

    if ($action -eq "ingest_records") {
        $rawRecords = @($msgObj.records)
        $enrichedList = @()
        $ackIds = @()
        if ($profileId -and -not $cfg.enrolled_profiles.ContainsKey($profileId)) {
            $autoEnrollRec = Format-EnrichedRecord @{
                id = "benroll-$profileId-auto"
                kind = "browser_enrollment"
                data = @{
                    profile_id = $profileId
                    profile_label = "Work Browser Profile"
                    browser_name = "Microsoft Edge"
                    browser_version = "130.0"
                    extension_version = "2.0.0"
                    status = "active"
                    enrolled_at = Get-UtcNowIso
                }
            } $identity $cfg $caller
            $enrichedList += ,$autoEnrollRec
            $cfg.enrolled_profiles[$profileId] = @{
                profile_label = "Work Browser Profile"
                enrolled_at = Get-UtcNowIso
                os_user = $identity.os_user
                os_sid = $identity.os_sid
            }
        }
        foreach ($r in $rawRecords) {
            if ($null -ne $r) {
                $er = Format-EnrichedRecord $r $identity $cfg $caller
                $enrichedList += ,$er
                $ackIds += ,[string]$er.id
            }
        }
        [void](Add-SpoolRecords $enrichedList)
        $fwd = Send-SpoolBatch $cfg
        if ($fwd.ok) {
            $cfg.last_delivery_at = Get-UtcNowIso
            Save-BridgeConfig $cfg
        }
        return @{
            ok = $true
            backend_delivered = [bool]$fwd.ok
            acknowledged = $ackIds
            os_user = $identity.os_user
            os_sid = $identity.os_sid
            device_hostname = $cfg.device_hostname
            queue_depth = $fwd.depth
            delivered_at = $cfg.last_delivery_at
            error = $fwd.error
        }
    }

    return @{ ok = $false; error = "Unsupported action: $action" }
}

$stdin = [Console]::OpenStandardInput()
$stdout = [Console]::OpenStandardOutput()

while ($true) {
    try {
        $lenBuf = New-Object byte[] 4
        $readLen = 0
        while ($readLen -lt 4) {
            $n = $stdin.Read($lenBuf, $readLen, 4 - $readLen)
            if ($n -le 0) { break }
            $readLen += $n
        }
        if ($readLen -eq 0) { break }
        if ($readLen -lt 4) { throw "Truncated native message length header" }

        $msgLen = [BitConverter]::ToUInt32($lenBuf, 0)
        if ($msgLen -le 0 -or $msgLen -gt $MaxMessageBytes) {
            throw "Native message size $msgLen exceeds limit ($MaxMessageBytes)"
        }

        $payloadBuf = New-Object byte[] $msgLen
        $totalRead = 0
        while ($totalRead -lt $msgLen) {
            $n = $stdin.Read($payloadBuf, $totalRead, $msgLen - $totalRead)
            if ($n -le 0) { throw "Truncated native message body" }
            $totalRead += $n
        }

        $jsonStr = [System.Text.Encoding]::UTF8.GetString($payloadBuf)
        $msgObj = $jsonStr | ConvertFrom-Json
        $respHashtable = Invoke-NativeMessage $msgObj $CallerOrigin
        $respJson = $respHashtable | ConvertTo-Json -Depth 10 -Compress
        $respBytes = [System.Text.Encoding]::UTF8.GetBytes($respJson)
        $outLenBytes = [BitConverter]::GetBytes([uint32]$respBytes.Length)
        $stdout.Write($outLenBytes, 0, 4)
        $stdout.Write($respBytes, 0, $respBytes.Length)
        $stdout.Flush()
    } catch {
        try {
            $errJson = @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
            $errBytes = [System.Text.Encoding]::UTF8.GetBytes($errJson)
            $outLenBytes = [BitConverter]::GetBytes([uint32]$errBytes.Length)
            $stdout.Write($outLenBytes, 0, 4)
            $stdout.Write($errBytes, 0, $errBytes.Length)
            $stdout.Flush()
        } catch {}
        break
    }
}
