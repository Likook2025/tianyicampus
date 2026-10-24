@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Read-only status of the no-GUI dialer. NO elevation needed, and it changes
rem  nothing: it only reports environment, auth state, service, pipe and
rem  whether the credential file is readable.
rem ============================================================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\src\TianyicampusDialer.ps1" -Status
echo.
pause