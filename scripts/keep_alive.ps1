$ErrorActionPreference = "SilentlyContinue"
$root = "C:\Users\ASUS\Documents\Codex\2026-10-02\read-start-here-astra-prompt-md\outputs\AD-Monitor"
$pyExe = "C:\Users\ASUS\Documents\Codex\2026-10-02\read-start-here-astra-prompt-md\work\.venv\Scripts\python.exe"

$env:PYTHONPATH = $root
$env:ADMONITOR_DB = "$root\data\admonitor.db"
$env:ADMONITOR_ALLOW_LAB_HTTP = "1"
$env:ADMONITOR_HOSTS = "localhost,127.0.0.1,0.0.0.0,::1,192.168.77.1,desktop-iaut7r9"

Set-Location $root

while ($true) {
    $listening = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
    if (-not $listening) {
        Start-Process -FilePath $pyExe -ArgumentList "-m uvicorn backend.api:app --host 0.0.0.0 --port 8765" -WorkingDirectory $root -WindowStyle Hidden
    }
    $guardian = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*scripts.guardian*"
    }
    if (-not $guardian) {
        Start-Process -FilePath $pyExe -ArgumentList "-m scripts.guardian" -WorkingDirectory $root -WindowStyle Hidden
    }
    Start-Sleep -Seconds 3
}
