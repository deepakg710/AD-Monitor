@echo off
setlocal
echo ==========================================================
echo  AD Monitor - Environment Installer
echo ==========================================================

cd /d "%~dp0\.."

echo [*] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python not found on PATH. Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

echo [*] Setting up virtual environment in .venv...
if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo [*] Installing backend dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo [*] Checking Node.js...
node -v >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Building frontend Single Page Application...
    cd frontend
    call npm.cmd install
    call npm.cmd run build
    cd ..
) else (
    echo [WARN] Node.js not detected. Pre-built frontend will be used if available.
)

echo.
echo [PASS] Installation complete!
echo Run scripts\start.bat to launch AD Monitor.
pause
