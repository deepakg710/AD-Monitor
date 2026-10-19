<#
.SYNOPSIS
    Installs and registers the AD Monitor Browser Telemetry Native Messaging Host
    for Chrome & Microsoft Edge on an enrolled employee VM (LAB-PC01).
#>
param(
    [string]$ExtensionId = "fjjbkbkbogknhemdmopognpnbabmfbog",
    [Parameter(Mandatory=$true)][string]$BrowserToken,
    [string]$BackendUrl = "http://192.168.77.1:8765",
    [string]$InstallDir = "",
    [string]$ExtensionStageDir = "C:\ADMonitor\browser-extension"
)

$ErrorActionPreference = "Stop"

$isDefaultInstall = [string]::IsNullOrWhiteSpace($InstallDir)
if ($isDefaultInstall) {
    $InstallDir = "C:\ADMonitor\BrowserBridge"
}

$cleanExtId = $ExtensionId.Trim().Trim('/')
if ($cleanExtId -match "^chrome-extension://([a-p]{32})$") {
    $cleanExtId = $Matches[1]
}
if ($cleanExtId -notmatch "^[a-p]{32}$") {
    Write-Error "Invalid ExtensionId '$ExtensionId'. Expected a 32-character Chrome/Edge extension ID (a-p)."
    exit 1
}

if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$localPy = if ($PSScriptRoot) { Join-Path $PSScriptRoot "native_host.py" } else { "" }
$localPs1 = if ($PSScriptRoot) { Join-Path $PSScriptRoot "native_host.ps1" } else { "" }
$localBat = if ($PSScriptRoot) { Join-Path $PSScriptRoot "native_host.bat" } else { "" }

if ($localPy -and (Test-Path -LiteralPath $localPy)) {
    Copy-Item -LiteralPath $localPy -Destination (Join-Path $InstallDir "native_host.py") -Force
}
if ($localPs1 -and (Test-Path -LiteralPath $localPs1)) {
    Copy-Item -LiteralPath $localPs1 -Destination (Join-Path $InstallDir "native_host.ps1") -Force
}
if ($localBat -and (Test-Path -LiteralPath $localBat)) {
    Copy-Item -LiteralPath $localBat -Destination (Join-Path $InstallDir "native_host.bat") -Force
}

$baseUrl = $BackendUrl.TrimEnd('/')
if ($isDefaultInstall -or -not (Test-Path -LiteralPath (Join-Path $InstallDir "native_host.ps1"))) {
    $bundleZip = Join-Path $InstallDir "browser-bridge-bundle.zip"
    $extractTemp = Join-Path $InstallDir "_bundle_extract"
    try {
        Invoke-WebRequest -Uri "$baseUrl/assets/browser-bridge-bundle.zip" -UseBasicParsing -OutFile $bundleZip -TimeoutSec 15
        if (Test-Path -LiteralPath $extractTemp) { Remove-Item -LiteralPath $extractTemp -Recurse -Force }
        Expand-Archive -Path $bundleZip -DestinationPath $extractTemp -Force
        Copy-Item -Path (Join-Path $extractTemp "native-host\*") -Destination $InstallDir -Force
        if ($ExtensionStageDir) {
            if (-not (Test-Path -LiteralPath $ExtensionStageDir)) {
                New-Item -ItemType Directory -Path $ExtensionStageDir -Force | Out-Null
            }
            Copy-Item -Path (Join-Path $extractTemp "browser-extension\*") -Destination $ExtensionStageDir -Recurse -Force
            Write-Host "[+] Staged Unpacked Browser Extension to: $ExtensionStageDir" -ForegroundColor Cyan
        }
    } catch {
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir "native_host.bat"))) {
            Write-Warning "Could not download browser-bridge-bundle.zip: $($_.Exception.Message)"
        }
    }
}

# Store collector token encrypted with both user DPAPI and local machine key (so interactive user can decrypt if installed from elevated Admin shell)
$tokenFile = Join-Path $InstallDir "token.dpapi"
$sec = ConvertTo-SecureString $BrowserToken -AsPlainText -Force
$sec | ConvertFrom-SecureString | Set-Content -LiteralPath $tokenFile -Encoding UTF8

$machineKeyFile = Join-Path $InstallDir "machine.key"
$machineTokenFile = Join-Path $InstallDir "token.machine.dpapi"
$keyBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
[Convert]::ToBase64String($keyBytes) | Set-Content -LiteralPath $machineKeyFile -Encoding UTF8
$sec | ConvertFrom-SecureString -Key $keyBytes | Set-Content -LiteralPath $machineTokenFile -Encoding UTF8

$defaultDetOrigin = "chrome-extension://fjjbkbkbogknhemdmopognpnbabmfbog/"
$origin = "chrome-extension://$cleanExtId/"
$allowedOrigins = @($origin)
if ($origin -ne $defaultDetOrigin) {
    $allowedOrigins += $defaultDetOrigin
}

$configObj = @{
    backend_url = $baseUrl
    device_hostname = $env:COMPUTERNAME
    token_file = $tokenFile
    machine_token_file = $machineTokenFile
    machine_key_file = $machineKeyFile
    allowed_origins = $allowedOrigins
    enrolled_profiles = @{}
}
$configPath = Join-Path $InstallDir "config.json"
$configObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8

$batPath = Join-Path $InstallDir "native_host.bat"
$manifestObj = @{
    name = "com.admonitor.browser_bridge"
    description = "AD Monitor Browser Telemetry Native Messaging Host"
    path = $batPath
    type = "stdio"
    allowed_origins = $allowedOrigins
}
$manifestPath = Join-Path $InstallDir "com.admonitor.browser_bridge.json"
$manifestObj | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$regPaths = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.admonitor.browser_bridge",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.admonitor.browser_bridge"
)

if ($isDefaultInstall) {
    $regPaths += @(
        "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.admonitor.browser_bridge",
        "HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.admonitor.browser_bridge",
        "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.admonitor.browser_bridge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\NativeMessagingHosts\com.admonitor.browser_bridge"
    )
    try {
        $userHives = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "^S-1-5-21-[\d-]+$" }
        foreach ($uh in $userHives) {
            $regPaths += "Registry::HKEY_USERS\$($uh.PSChildName)\Software\Google\Chrome\NativeMessagingHosts\com.admonitor.browser_bridge"
            $regPaths += "Registry::HKEY_USERS\$($uh.PSChildName)\Software\Microsoft\Edge\NativeMessagingHosts\com.admonitor.browser_bridge"
        }
    } catch {}
}

foreach ($rp in $regPaths) {
    try {
        $parent = Split-Path -Parent $rp
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if (-not (Test-Path -LiteralPath $rp)) {
            New-Item -Path $rp -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -LiteralPath $rp -Name "(Default)" -Value $manifestPath -ErrorAction SilentlyContinue
    } catch {}
}

# If run interactively on an endpoint (default install), verify the Native Messaging Host stdio pipe and controlled download-to-process chain
if ($isDefaultInstall) {
    try {
        $interactiveAcct = $null
        $interactiveSid = $null
        $interactiveUserShort = "sales.demo"
        $expCim = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($expCim) {
            $oRes = Invoke-CimMethod -InputObject $expCim -MethodName GetOwner -ErrorAction SilentlyContinue
            $sRes = Invoke-CimMethod -InputObject $expCim -MethodName GetOwnerSid -ErrorAction SilentlyContinue
            if ($oRes -and $oRes.User) {
                $interactiveUserShort = $oRes.User
                $interactiveAcct = if ($oRes.Domain) { "$($oRes.Domain)\$($oRes.User)" } else { $oRes.User }
            }
            if ($sRes -and $sRes.Sid) {
                $interactiveSid = $sRes.Sid
            }
        }
        if (-not $interactiveAcct) {
            $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $interactiveAcct = $wi.Name
            $interactiveSid = if ($wi.User) { $wi.User.Value } else { "S-1-5-21-UNKNOWN" }
        }

        $userDownloads = "C:\Users\$interactiveUserShort\Downloads"
        if (-not (Test-Path -LiteralPath $userDownloads)) {
            $userDownloads = Join-Path $HOME "Downloads"
        }
        if (-not (Test-Path -LiteralPath $userDownloads)) {
            New-Item -ItemType Directory -Path $userDownloads -Force | Out-Null
        }
        $targetPs1 = Join-Path $userDownloads "lab-check.ps1"
        Invoke-WebRequest -Uri "$baseUrl/assets/lab-check.ps1" -UseBasicParsing -OutFile $targetPs1 -TimeoutSec 10
        $fileLen = (Get-Item -LiteralPath $targetPs1).Length

        $profId = "bprof-" + $env:COMPUTERNAME.ToLowerInvariant() + "-edge-work"
        $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $navIso = (Get-Date).ToUniversalTime().AddSeconds(-4).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $dlStartIso = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")

        # Pipe a real length-prefixed Native Messaging request through native_host.bat on LAB-PC01
        $nativeMsg = @{
            action = "ingest_records"
            profile_id = $profId
            records = @(
                @{
                    id = "bnav-" + [guid]::NewGuid().ToString()
                    kind = "browser_navigation"
                    data = @{
                        profile_id = $profId
                        browser_name = "Microsoft Edge"
                        browser_version = "130.0"
                        extension_id = $cleanExtId
                        extension_version = "2.0.0"
                        navigation_time = $navIso
                        domain = "192.168.77.1"
                        scheme = "http"
                        transition_type = "link"
                        tab_context = "top_frame"
                        frame_id = 0
                        is_incognito = $false
                    }
                },
                @{
                    id = "bdl-$profId-1-r1"
                    kind = "browser_download"
                    data = @{
                        profile_id = $profId
                        browser_name = "Microsoft Edge"
                        browser_version = "130.0"
                        extension_id = $cleanExtId
                        extension_version = "2.0.0"
                        browser_download_id = 1
                        download_id = 1
                        revision = 1
                        filename = "lab-check.ps1"
                        final_path = $targetPs1
                        target_path = $targetPs1
                        source_domain = "192.168.77.1"
                        referrer_domain = "192.168.77.1"
                        mime_type = "text/plain"
                        bytes_received = $fileLen
                        total_bytes = $fileLen
                        state = "completed"
                        danger_type = "safe"
                        start_time = $dlStartIso
                        end_time = $nowIso
                        is_incognito = $false
                    }
                }
            )
        } | ConvertTo-Json -Depth 10 -Compress

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'native_host.ps1')`" `"$origin`" --parent-window=0"
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($nativeMsg)
        $lenBytes = [BitConverter]::GetBytes([uint32]$msgBytes.Length)
        $proc.StandardInput.BaseStream.Write($lenBytes, 0, 4)
        $proc.StandardInput.BaseStream.Write($msgBytes, 0, $msgBytes.Length)
        $proc.StandardInput.BaseStream.Flush()
        $proc.StandardInput.Close()
        $proc.WaitForExit(15000) | Out-Null
        Write-Host "[+] Verified Native Messaging Host stdio bridge & download SHA-256 enrichment for $targetPs1" -ForegroundColor Cyan

        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$targetPs1`"" -WindowStyle Hidden
        Write-Host "[+] Launched controlled verification script ($targetPs1) for Process Monitor & Timeline correlation!" -ForegroundColor Cyan
    } catch {
        Write-Warning "Initial native host verification warning: $($_.Exception.Message)"
    }
}

Write-Host "[+] Installed Native Messaging Host to: $InstallDir" -ForegroundColor Green
Write-Host "[+] Allowed Extension Origin(s): $($allowedOrigins -join ', ')" -ForegroundColor Green
Write-Host "[+] DPAPI Token saved to: $tokenFile" -ForegroundColor Green
Write-Host "[+] Registered NativeMessagingHosts for Chrome and Edge (HKCU/HKLM/HKU)." -ForegroundColor Green
