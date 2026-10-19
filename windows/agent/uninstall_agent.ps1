<#
.SYNOPSIS
    Uninstalls the AD Monitor Endpoint Agent scheduled task.
#>
$taskName = "ADMonitorEndpointAgent"

try {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "[+] Scheduled task '$taskName' removed." -ForegroundColor Green
} catch {
    Write-Warning "[-] Could not unregister task '$taskName': $($_.Exception.Message)"
}
