<#
.SYNOPSIS
    Uninstalls the AD Monitor Browser Telemetry Native Messaging Host for the current user.
#>
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\ADMonitor\BrowserBridge"
)

$regPaths = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.admonitor.browser_bridge",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.admonitor.browser_bridge"
)

foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        Remove-Item -Path $rp -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed registry key: $rp" -ForegroundColor Yellow
    }
}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed Native Host directory: $InstallDir" -ForegroundColor Yellow
}
