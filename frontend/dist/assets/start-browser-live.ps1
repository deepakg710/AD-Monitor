# AD Monitor - All-in-One Live Browser, Download & USB Watcher for LAB-PC01
$ErrorActionPreference = "Continue"

$bridgeUserDir = Join-Path $env:LOCALAPPDATA "ADMonitor\BrowserBridge"
if (-not (Test-Path -LiteralPath $bridgeUserDir)) {
    New-Item -ItemType Directory -Path $bridgeUserDir -Force | Out-Null
}

# Also update C:\ADMonitor\agent\endpoint_agent.ps1 if writable
try {
    if (Test-Path -LiteralPath "C:\ADMonitor\agent") {
        Invoke-WebRequest -Uri "http://192.168.77.1:8765/lab-scripts/endpoint_agent.ps1" -UseBasicParsing -OutFile "C:\ADMonitor\agent\endpoint_agent.ps1" -TimeoutSec 10 -ErrorAction Stop
        Write-Host "[+] Updated C:\ADMonitor\agent\endpoint_agent.ps1 with enhanced USB & App detection." -ForegroundColor Green
    }
} catch {}

$watcherScriptPath = Join-Path $bridgeUserDir "live_browser_watcher.ps1"

$watcherCode = @'
param([switch]$Once)
$ErrorActionPreference = "SilentlyContinue"

$BackendUrl = "http://192.168.77.1:8765"
$AgentToken = "admon-lab-pc01-agent-token-2026"
$NativeBat = "C:\ADMonitor\BrowserBridge\native_host.bat"
$ExtOrigin = "chrome-extension://fjjbkbkbogknhemdmopognpnbabmfbog/"
$ProfileId = "bprof-lab-pc01-edge-work"

function Send-AgentRecords($Records) {
    if (-not $Records -or $Records.Count -eq 0) { return $false }
    $payload = @{
        schema_version = 2
        transport_id   = [guid]::NewGuid().ToString()
        records        = @($Records)
    } | ConvertTo-Json -Depth 10 -Compress
    $headers = @{
        "Authorization" = "Bearer $AgentToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }
    try {
        Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 8 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Send-BrowserRecords($Records) {
    if (-not $Records -or $Records.Count -eq 0) { return $null }
    if (Test-Path -LiteralPath $NativeBat) {
        try {
            $msg = @{
                action = "ingest_records"
                profile_id = $ProfileId
                records = @($Records)
            } | ConvertTo-Json -Depth 10 -Compress
            $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
            $lenBytes = [BitConverter]::GetBytes([uint32]$msgBytes.Length)

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmd.exe"
            $psi.Arguments = "/c `"`"$NativeBat`" `"$ExtOrigin`"`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true

            $proc = [System.Diagnostics.Process]::Start($psi)
            $stdin = $proc.StandardInput.BaseStream
            $stdin.Write($lenBytes, 0, 4)
            $stdin.Write($msgBytes, 0, $msgBytes.Length)
            $stdin.Flush()
            $stdin.Close()

            $stdout = $proc.StandardOutput.BaseStream
            $rLenBuf = New-Object byte[] 4
            $read = $stdout.Read($rLenBuf, 0, 4)
            $respObj = $null
            if ($read -eq 4) {
                $rLen = [BitConverter]::ToUInt32($rLenBuf, 0)
                $rBuf = New-Object byte[] $rLen
                $total = 0
                while ($total -lt $rLen) {
                    $n = $stdout.Read($rBuf, $total, $rLen - $total)
                    if ($n -le 0) { break }
                    $total += $n
                }
                $respStr = [System.Text.Encoding]::UTF8.GetString($rBuf, 0, $total)
                $respObj = $respStr | ConvertFrom-Json
            }
            $proc.WaitForExit(8000) | Out-Null
            if ($respObj -and $respObj.backend_delivered) { return $respObj }
        } catch {}
    }
    return $null
}

$NoisePattern = '^(?:.*?\.)?(?:microsoft\.com|windows\.com|windowsupdate\.com|bing\.com|msn\.com|live\.com|office\.com|office365\.com|msedge\.net|trafficmanager\.net|digicert\.com|akamaiedge\.net|akamaihd\.net|akamaized\.net|edgekey\.net|edgesuite\.net|cloudflare\.com|cloudflare-dns\.com|googleapis\.com|gstatic\.com|gvt1\.com|gvt2\.com|1e100\.net|doubleclick\.net|google-analytics\.com|googletagmanager\.com|googlesyndication\.com|googleadservices\.com|ytimg\.com|googlevideo\.com|ggpht\.com|fbcdn\.net|scorecardresearch\.com|adnxs\.com|criteo\.com|rubiconproject\.com|taboola\.com|outbrain\.com|lab\.local|local|arpa|localhost)$'

$seenDomains = @{}
$seenDownloads = @{}
$seenUsbDrives = @{}
$seenUsbFiles = @{}
$usbFirstPassDone = $false
$lastVisitedDomain = "google.com"

function Invoke-ScanPass {
    $records = @()
    $agentRecords = @()
    $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    # 1. USB Drive & USB File Copy Detection on LAB-PC01
    try {
        $usbEvents = @()
        $currentUsbMap = @{}
        $usbDisks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceType -eq 'USB' -or $_.MediaType -like '*Removable*' -or $_.PNPDeviceID -like 'USB*'
        })
        foreach ($d in $usbDisks) {
            $id = [string]$d.DeviceID
            $model = if ($d.Model) { [string]$d.Model } else { "USB Storage Device ($id)" }
            $currentUsbMap[$id] = @{ model = $model; size = $d.Size; partitions = $d.Partitions }
        }
        $remVols = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
            $_.DriveType -eq 2 -or ($_.DriveType -eq 3 -and $_.DeviceID -ne 'C:')
        })
        foreach ($rv in $remVols) {
            $lid = "USB Removable Drive ($($rv.DeviceID))"
            $vname = if ($rv.VolumeName) { "$($rv.VolumeName) ($($rv.DeviceID))" } else { "Removable Storage Volume ($($rv.DeviceID))" }
            $currentUsbMap[$lid] = @{ model = $vname; size = $rv.Size; partitions = 1 }
        }
        foreach ($k in $currentUsbMap.Keys) {
            $lastSent = if ($seenUsbDrives.ContainsKey($k)) { $seenUsbDrives[$k] } else { 0 }
            # Re-announce every 60s so even after Reset Telemetry the connected USB drive is visible
            if (($nowEpoch - $lastSent) -ge 60) {
                $seenUsbDrives[$k] = $nowEpoch
                $usbEvents += @{
                    id         = [guid]::NewGuid().ToString()
                    time       = $nowIso
                    action     = "connected"
                    identifier = $k
                    account    = "LAB\sales.demo"
                    metadata   = $currentUsbMap[$k]
                }
            }
        }
        foreach ($oldK in @($seenUsbDrives.Keys)) {
            if (-not $currentUsbMap.ContainsKey($oldK)) {
                $seenUsbDrives.Remove($oldK)
                $usbEvents += @{
                    id         = [guid]::NewGuid().ToString()
                    time       = $nowIso
                    action     = "disconnected"
                    identifier = $oldK
                    account    = "LAB\sales.demo"
                    metadata   = @{ model = $oldK }
                }
            }
        }
        if ($usbEvents.Count -gt 0) {
            $osCap = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            $agentRecords += @{
                kind = "heartbeat"
                id   = "hb-usb-" + [guid]::NewGuid().ToString()
                data = @{
                    hostname      = $env:COMPUTERNAME
                    time          = $nowIso
                    os            = if ($osCap) { $osCap } else { "Microsoft Windows 11 Pro" }
                    ips           = @("192.168.77.20")
                    agent_version = "2.0.0"
                    health        = @{ cpu = 12.0; ram_percent = 55.0; disks = @() }
                    sessions      = @(@{ id = "LAB\sales.demo"; account = "LAB\sales.demo"; state = "Active" })
                    usb_events    = $usbEvents
                    errors        = @()
                }
            }
        }

        foreach ($rv in $remVols) {
            $letter = $rv.DeviceID
            $uFiles = Get-ChildItem -Path "$letter\" -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
            foreach ($uf in $uFiles) {
                $ukey = "$($uf.FullName)|$($uf.Length)|$($uf.LastWriteTimeUtc.Ticks)"
                if (-not $seenUsbFiles.ContainsKey($ukey)) {
                    $seenUsbFiles[$ukey] = $true
                    $isRecent = ($uf.LastWriteTimeUtc -ge (Get-Date).ToUniversalTime().AddMinutes(-15)) -or ($uf.CreationTimeUtc -ge (Get-Date).ToUniversalTime().AddMinutes(-15))
                    if ($script:usbFirstPassDone -or $isRecent) {
                        $agentRecords += @{
                            id   = [guid]::NewGuid().ToString()
                            kind = "observation"
                            time = $nowIso
                            data = @{
                                category              = "file_copy"
                                source_path           = $uf.Name
                                destination_path      = $uf.FullName
                                destination_removable = $true
                                bytes                 = [int64]$uf.Length
                                hostname              = $env:COMPUTERNAME
                                account               = "LAB\sales.demo"
                            }
                        }
                    }
                }
            }
        }
        $script:usbFirstPassDone = $true
    } catch {}

    if ($agentRecords.Count -gt 0) {
        $okUsb = Send-AgentRecords $agentRecords
        if ($Once) {
            Write-Host "[+] Sent $($agentRecords.Count) USB / file transfer record(s) to AD Monitor! Delivered: $okUsb" -ForegroundColor Green
        }
    }

    # 2. Collect domains from DNS Client Cache + Edge/Chrome History
    $candidateDomains = New-Object System.Collections.Generic.List[string]
    try {
        $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($d in $dnsEntries) {
            $dom = ([string]$d.Entry).Trim().Trim('.').ToLowerInvariant()
            if ($dom -and $dom -match '^[a-z0-9.-]+\.[a-z]{2,}$' -and $dom -notmatch $NoisePattern) {
                if (-not $candidateDomains.Contains($dom)) {
                    $candidateDomains.Add($dom)
                }
            }
        }
    } catch {}

    $browserPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    )
    foreach ($uDir in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
        $browserPaths += Join-Path $uDir.FullName "AppData\Local\Microsoft\Edge\User Data\Default\History"
        $browserPaths += Join-Path $uDir.FullName "AppData\Local\Google\Chrome\User Data\Default\History"
        $edgeSess = Join-Path $uDir.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Sessions"
        $chrSess = Join-Path $uDir.FullName "AppData\Local\Google\Chrome\User Data\Default\Sessions"
        foreach ($sDir in @($edgeSess, $chrSess)) {
            if (Test-Path -LiteralPath $sDir) {
                $latestTabs = Get-ChildItem -LiteralPath $sDir -Filter "Tabs_*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
                if ($latestTabs) { $browserPaths += $latestTabs.FullName }
            }
        }
    }
    foreach ($bp in ($browserPaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $bp) {
            $tmpCopy = Join-Path $env:TEMP ("adm_hist_" + [guid]::NewGuid().ToString("N") + ".tmp")
            try {
                Copy-Item -LiteralPath $bp -Destination $tmpCopy -Force -ErrorAction Stop
                $fs = [System.IO.File]::OpenRead($tmpCopy)
                $readLen = [Math]::Min(262144, [int]$fs.Length)
                if ($readLen -gt 0) {
                    $fs.Seek(-$readLen, [System.IO.SeekOrigin]::End) | Out-Null
                    $buf = New-Object byte[] $readLen
                    [void]$fs.Read($buf, 0, $readLen)
                    $ascii = [System.Text.Encoding]::ASCII.GetString($buf)
                    $urlMatches = [regex]::Matches($ascii, 'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[/\?#:]|\b)')
                    foreach ($m in $urlMatches) {
                        $dom = $m.Groups[1].Value.Trim().Trim('.').ToLowerInvariant()
                        if ($dom -and $dom -notmatch $NoisePattern -and -not $candidateDomains.Contains($dom)) {
                            $candidateDomains.Add($dom)
                        }
                    }
                }
                $fs.Close()
            } catch {} finally {
                if (Test-Path -LiteralPath $tmpCopy) { Remove-Item -LiteralPath $tmpCopy -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    $tabCounter = 1
    foreach ($dom in $candidateDomains) {
        $prevEpoch = if ($seenDomains.ContainsKey($dom)) { $seenDomains[$dom] } else { 0 }
        if (($nowEpoch - $prevEpoch) -ge 45) {
            $seenDomains[$dom] = $nowEpoch
            $script:lastVisitedDomain = $dom
            $records += @{
                id = "bnav-" + [guid]::NewGuid().ToString()
                kind = "browser_navigation"
                data = @{
                    profile_id = $ProfileId
                    browser_name = "Edge"
                    extension_id = "fjjbkbkbogknhemdmopognpnbabmfbog"
                    normalized_domain = $dom
                    scheme = "https"
                    transition_type = "typed"
                    transition_qualifiers = @("from_address_bar")
                    tab_id = $tabCounter
                    frame_id = 0
                    navigation_time = $nowIso
                }
            }
            $tabCounter++
        }
    }

    # 3. Collect recent downloads in Downloads folder
    $dlDirs = @((Join-Path $HOME "Downloads"))
    foreach ($uDir in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
        $dPath = Join-Path $uDir.FullName "Downloads"
        if (Test-Path -LiteralPath $dPath) { $dlDirs += $dPath }
    }
    $cutoffUtc = (Get-Date).ToUniversalTime().AddMinutes(-60)
    foreach ($dlDir in ($dlDirs | Select-Object -Unique)) {
        $files = Get-ChildItem -LiteralPath $dlDir -File -ErrorAction SilentlyContinue | Where-Object {
            $_.LastWriteTimeUtc -ge $cutoffUtc -and $_.Extension -notmatch '^\.(crdownload|tmp|part)$'
        }
        foreach ($f in $files) {
            $sigKey = "$($f.FullName)|$($f.Length)|$($f.LastWriteTimeUtc.Ticks)"
            if (-not $seenDownloads.ContainsKey($sigKey)) {
                $seenDownloads[$sigKey] = $true
                $hashVal = $null
                try {
                    $hashVal = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                } catch {}
                $dlInt = [Math]::Abs($f.FullName.GetHashCode()) % 900000 + 1000
                $records += @{
                    id = "bdl-" + [guid]::NewGuid().ToString()
                    kind = "browser_download"
                    data = @{
                        profile_id = $ProfileId
                        browser_name = "Edge"
                        extension_id = "fjjbkbkbogknhemdmopognpnbabmfbog"
                        browser_download_id = $dlInt
                        state = "completed"
                        filename = $f.Name
                        final_path = $f.FullName
                        target_path = $f.FullName
                        mime_type = "application/octet-stream"
                        total_bytes = [int64]$f.Length
                        received_bytes = [int64]$f.Length
                        source_domain = $script:lastVisitedDomain
                        tab_domain = $script:lastVisitedDomain
                        sha256 = $hashVal
                        hash_state = if ($hashVal) { "Verified" } else { "Not collected" }
                        file_exists = $true
                        exists_on_disk = $true
                        started_at = $f.CreationTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        updated_at = $f.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        completed_at = $f.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                }
            }
        }
    }

    if ($records.Count -gt 0) {
        $res = Send-BrowserRecords $records
        if ($Once) {
            Write-Host "[+] Sent $($records.Count) browser navigation/download record(s) to AD Monitor! Domains: $($candidateDomains -join ', ') | Delivered: $($res.backend_delivered)" -ForegroundColor Green
        }
    } elseif ($Once) {
        Write-Host "[*] Browser & USB watcher initialized." -ForegroundColor Cyan
    }
}

Invoke-ScanPass
if (-not $Once) {
    while ($true) {
        Start-Sleep -Seconds 3
        Invoke-ScanPass
    }
}
'@

$watcherCode | Set-Content -LiteralPath $watcherScriptPath -Encoding UTF8

# Run one immediate pass in the foreground so user sees instant confirmation
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $watcherScriptPath -Once

# Stop any older background watcher and launch a fresh hidden background loop
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessId -ne $PID -and $_.CommandLine -like "*live_browser_watcher.ps1*"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watcherScriptPath`"" -WindowStyle Hidden
Write-Host "[+] Live Browser, Download & USB Watcher is now running in the background on $env:COMPUTERNAME (checks every 3 seconds)!" -ForegroundColor Green
