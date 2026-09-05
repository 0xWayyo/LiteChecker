@echo off
setlocal
call "%~dp0LiteChecker.bat"
set "installExit=%errorlevel%"
exit /b %installExit%
