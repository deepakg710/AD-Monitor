@echo off
echo Stopping AD Monitor processes...
taskkill /f /im python.exe /fi "WINDOWTITLE eq AD Monitor*" >nul 2>&1
echo Done.
pause
