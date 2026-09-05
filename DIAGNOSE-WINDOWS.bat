@echo off
setlocal
set "LITECHECKER_ROOT=%~dp0"
set "LITECHECKER_SCRIPT=%LITECHECKER_ROOT%_app\scripts\windows-native.ps1"
if not exist "%LITECHECKER_SCRIPT%" set "LITECHECKER_SCRIPT=%LITECHECKER_ROOT%scripts\windows-native.ps1"
if not exist "%LITECHECKER_SCRIPT%" (
  echo LiteChecker Windows diagnostics launcher is incomplete. Extract the whole ZIP first.
  exit /b 2
)

set "LITECHECKER_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "LITECHECKER_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%LITECHECKER_POWERSHELL%" (
  echo Windows PowerShell 5.1 was not found.
  exit /b 2
)

"%LITECHECKER_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%LITECHECKER_SCRIPT%" -Root "%LITECHECKER_ROOT%." -Action Diagnose
set "LITECHECKER_RESULT=%ERRORLEVEL%"
if not "%LITECHECKER_RESULT%"=="0" (
  echo.
  echo LiteChecker Windows diagnostics finished with code %LITECHECKER_RESULT%.
)
pause
exit /b %LITECHECKER_RESULT%
