@echo off
chcp 65001 >nul
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -NoLogo -File "%~dp0..\tests\Invoke-GuardTests.ps1"
set RC=%ERRORLEVEL%
echo.
echo Exit code: %RC%
echo.
pause
exit /b %RC%
