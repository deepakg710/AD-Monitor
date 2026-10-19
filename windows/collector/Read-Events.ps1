param([Parameter(Mandatory)][string]$RequestFile)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$r = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$records = [System.Collections.Generic.List[object]]::new()
$states = @{}
$errors = [System.Collections.Generic.List[string]]::new()
$allowed = @('Security','ForwardedEvents','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-PowerShell/Operational')
foreach ($source in $r.sources) {
    $reader = $null
    try {
        $channel = [string]$source.channel
        if ($channel -notin $allowed) { throw "Unsupported channel: $channel" }
        $since = [DateTimeOffset]::Parse([string]$source.since).UtcDateTime.ToString('o')
        $xpath = "*[System[TimeCreated[@SystemTime >= '$since']]]"
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($channel,[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
        $query.ReverseDirection = $false
        if ($source.bookmark) {
            try {
                $bookmark = [System.Diagnostics.Eventing.Reader.EventBookmark]::new([string]$source.bookmark)
                $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query,$bookmark)
                # A stale bookmark can fail on first ReadEvent, handled by the outer catch.
            } catch {
                $errors.Add("Bookmark reset for $channel; replaying retained records from $since. Events already purged cannot be recovered.")
                $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
            }
        } else { $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query) }
        for ($i=0; $i -lt 25; $i++) {
            try { $event = $reader.ReadEvent([TimeSpan]::FromSeconds(2)) }
            catch {
                if ($source.bookmark) {
                    $reader.Dispose(); $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
                    $errors.Add("Channel reset or rollover on $channel; bounded timestamp replay from $since. Possible gap if old records were purged.")
                    $source.bookmark = $null
                    $event = $reader.ReadEvent([TimeSpan]::FromSeconds(2))
                } else { throw }
            }
            if ($null -eq $event) { break }
            try {
                $xml = $event.ToXml()
                if ([Text.Encoding]::UTF8.GetByteCount($xml) -gt 131072) { throw 'Oversized source event: collection paused at this record; configure an explicit source exclusion after review.' }
                $records.Add(@{ xml=$xml; channel=$channel; bookmark=$event.Bookmark.BookmarkXml; time=$event.TimeCreated.ToUniversalTime().ToString('o') })
                $states[$channel] = @{ bookmark=$event.Bookmark.BookmarkXml; last_time=$event.TimeCreated.ToUniversalTime().ToString('o') }
            } finally { $event.Dispose() }
        }
    } catch { $errors.Add("$($source.channel): $($_.Exception.Message)") }
    finally { if ($reader) { $reader.Dispose() } }
}
@{records=@($records.ToArray()); states=$states; errors=@($errors.ToArray())} | ConvertTo-Json -Depth 12 -Compress
