@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0INSTALL.ps1"
set "installExit=%errorlevel%"
echo.
pause
exit /b %installExit%
