@echo off
setlocal
cd /d "%~dp0\.."

set PYTHON_CMD=python
if exist ".venv\Scripts\python.exe" set PYTHON_CMD=.venv\Scripts\python.exe
if exist "..\..\work\.venv\Scripts\python.exe" set PYTHON_CMD=..\..\work\.venv\Scripts\python.exe

set PYTHONPATH=.

echo ==========================================================
echo  AD Monitor - Running Automated Pytest Suite
echo ==========================================================
%PYTHON_CMD% -m pytest -v
pause
