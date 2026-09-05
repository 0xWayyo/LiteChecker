@echo off
setlocal
set "LITECHECKER_APP=%~dp0_app"
set "LITECHECKER_ROOT=%~dp0_app\."
set "LITECHECKER_PS=%LITECHECKER_APP%\scripts\windows-native.ps1"
if not exist "%LITECHECKER_PS%" (
  if exist "%~dp0pyproject.toml" if exist "%~dp0CONTENTS.sha256.json" if exist "%~dp0scripts\windows-native.ps1" (
    set "LITECHECKER_APP=%~dp0."
    set "LITECHECKER_ROOT=%~dp0."
    set "LITECHECKER_PS=%~dp0scripts\windows-native.ps1"
  )
)
if not exist "%LITECHECKER_PS%" (
  echo LiteChecker: archive is incomplete. Extract the ZIP again.
  pause
  exit /b 2
)
set "LITECHECKER_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "LITECHECKER_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%LITECHECKER_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%LITECHECKER_PS%" -Root "%LITECHECKER_ROOT%" -Action App
set "LITECHECKER_EXIT=%ERRORLEVEL%"
if not "%LITECHECKER_EXIT%"=="0" pause
exit /b %LITECHECKER_EXIT%
