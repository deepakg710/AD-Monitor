@echo off
setlocal
echo ==========================================================
echo  AD Monitor - Starting Server
echo ==========================================================

cd /d "%~dp0\.."

set PYTHON_CMD=python
if exist ".venv\Scripts\python.exe" set PYTHON_CMD=.venv\Scripts\python.exe
if exist "..\..\work\.venv\Scripts\python.exe" set PYTHON_CMD=..\..\work\.venv\Scripts\python.exe

set PYTHONPATH=.
set ADMONITOR_HOSTS=localhost,127.0.0.1,::1,192.168.77.1
set ADMONITOR_ALLOW_LAB_HTTP=1

echo [*] Starting AD Monitor server on http://0.0.0.0:8765 ...
echo [*] Local UI: http://localhost:8765
echo [*] Lab VMs:  http://192.168.77.1:8765
echo [*] First-time admin setup: python -m backend.cli create-admin --username ^<admin_username^>
echo [*] Press Ctrl+C to stop.
echo.

%PYTHON_CMD% -m uvicorn backend.app:make_app --factory --host 0.0.0.0 --port 8765
pause
