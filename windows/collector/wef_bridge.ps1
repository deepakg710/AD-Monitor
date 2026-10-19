<#
.SYNOPSIS
    AD Monitor - Windows Event Forwarding (WEF) Collector Bridge
.DESCRIPTION
    Runs on the Domain Controller (WIN-8IIRPFSV4GI) or WEF collector.
    Reads events incrementally from 'ForwardedEvents' (or 'Security') in chronological order (-Oldest)
    using durable bookmarks, batches records with versioned schema_version=2 and transport_id,
    and reliably forwards them to the AD Monitor backend ingestion API with a bounded local queue.
#>

param (
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$CollectorToken = "",
    [string]$TokenFile = "$PSScriptRoot\token.dpapi",
    [string]$Channel = "ForwardedEvents",
    [int]$BatchSize = 50,
    [int]$PollIntervalSeconds = 5,
    [string]$BookmarkFile = "$PSScriptRoot\wef_bookmark.xml",
    [string]$QueueDir = "$PSScriptRoot\queue",
    [int]$MaxQueueFiles = 200
)

$ErrorActionPreference = "Continue"

if (-not $CollectorToken -and (Test-Path $TokenFile)) {
    try {
        $sec = Get-Content -Path $TokenFile -Raw | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        $CollectorToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    } catch {
        Write-Warning "Could not decrypt token file $TokenFile : $($_.Exception.Message)"
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD Monitor - WEF Collector Bridge (v2.0)" -ForegroundColor Cyan
Write-Host " Channel: $Channel" -ForegroundColor Cyan
Write-Host " Backend: $BackendUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not $CollectorToken) {
    Write-Warning "No CollectorToken specified. Please enroll a collector in the AD Monitor dashboard or pass -CollectorToken."
    return
}

if (-not (Test-Path $QueueDir)) {
    New-Item -ItemType Directory -Path $QueueDir -Force | Out-Null
}

function Send-Batch {
    param (
        [array]$Records
    )
    if ($Records.Count -eq 0) { return $true }

    $transportId = [guid]::NewGuid().ToString()
    $bodyObj = @{
        schema_version = 2
        transport_id = $transportId
        records = @($Records)
        checkpoints = @{ $Channel = "$($Records[-1].id)" }
    }
    $body = $bodyObj | ConvertTo-Json -Depth 8 -Compress

    $headers = @{
        "Authorization" = "Bearer $CollectorToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $body -TimeoutSec 15
        $ackCount = if ($null -ne $response.acknowledged) { @($response.acknowledged).Count } else { @($response.accepted).Count }
        Write-Host "[+] Forwarded $($Records.Count) events (Acknowledged: $ackCount, Duplicates: $(@($response.duplicates).Count))" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "[-] Ingestion failed: $($_.Exception.Message). Queuing records locally."
        $existing = @(Get-ChildItem -Path $QueueDir -Filter "queue_*.json" -ErrorAction SilentlyContinue | Sort-Object CreationTime)
        if ($existing.Count -ge $MaxQueueFiles) {
            $dropCount = ($existing.Count - $MaxQueueFiles) + 1
            $existing | Select-Object -First $dropCount | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        $qFile = Join-Path $QueueDir "queue_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())_$transportId.json"
        $body | Set-Content -Path $qFile -Encoding UTF8
        return $false
    }
}

function Flush-Queue {
    $queuedFiles = @(Get-ChildItem -Path $QueueDir -Filter "queue_*.json" -ErrorAction SilentlyContinue | Sort-Object CreationTime)
    foreach ($file in $queuedFiles) {
        try {
            $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
            $headers = @{
                "Authorization" = "Bearer $CollectorToken"
                "Content-Type" = "application/json"
            }
            $null = Invoke-RestMethod -Uri "$BackendUrl/api/ingest" -Method Post -Headers $headers -Body $content -TimeoutSec 15
            Write-Host "[+] Flushed queued file: $($file.Name)" -ForegroundColor Green
            Remove-Item -Path $file.FullName -Force
        }
        catch {
            Write-Warning "[-] Retry queue flush failed: $($_.Exception.Message)"
            break
        }
    }
}

# Load or initialize bookmark
$lastRecordId = 0
if (Test-Path $BookmarkFile) {
    try {
        [xml]$bm = Get-Content -Path $BookmarkFile
        $lastRecordId = [int64]$bm.Bookmark.RecordId
        Write-Host "[*] Resuming from bookmark RecordId: $lastRecordId" -ForegroundColor Gray
    } catch {
        Write-Warning "[-] Could not read bookmark file. Starting fresh."
    }
}

# Ensure Audit Policy is enabled for Logon (4625), Kerberos Pre-Auth (4771), Credential Validation (4776), and Process Creation (4688/4689)
try {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable 2>&1 | Out-Null
    Write-Host "[+] Enabled Audit policy for Logon, Kerberos, Account Management, and Process Creation/Termination." -ForegroundColor Green
} catch {}

Write-Host "[*] Starting chronological event collection loop (-Oldest). Press Ctrl+C to stop." -ForegroundColor Yellow

while ($true) {
    Flush-Queue

    try {
        $filterXPath = "*[System[(EventRecordID > $lastRecordId)]]"
        # -Oldest ensures backlog records are read in ascending RecordId order without skipping older events
        $events = Get-WinEvent -LogName $Channel -FilterXPath $filterXPath -MaxEvents $BatchSize -Oldest -ErrorAction SilentlyContinue

        if ($events) {
            $events = @($events) | Sort-Object RecordId
            $batch = @()

            foreach ($evt in $events) {
                try {
                    $xml = $evt.ToXml()
                    $rec = @{
                        kind = "windows"
                        id = "$Channel`:$($evt.RecordId)"
                        xml = $xml
                    }
                    $batch += $rec
                    $lastRecordId = $evt.RecordId
                }
                catch {
                    Write-Warning "Failed to serialize event: $($_.Exception.Message)"
                }
            }

            if ($batch.Count -gt 0) {
                $sent = Send-Batch -Records $batch
                if ($sent) {
                    "<Bookmark><RecordId>$lastRecordId</RecordId><Timestamp>$([DateTime]::UtcNow.ToString('o'))</Timestamp></Bookmark>" | Set-Content -Path $BookmarkFile -Encoding UTF8
                }
            }
        }
    }
    catch {
        Write-Warning "[-] Event log query error on channel '$Channel': $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
