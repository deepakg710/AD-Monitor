@echo off
setlocal
if defined ADMONITOR_PYTHON (
    "%ADMONITOR_PYTHON%" -u "%~dp0native_host.py" "%~1"
) else if exist "%~dp0native_host.ps1" (
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0native_host.ps1" "%~1"
) else (
    python -u "%~dp0native_host.py" "%~1"
)
