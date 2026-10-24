@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Run one real dial attempt right now (no GUI, no clicking), then exit.
rem
rem  Needs elevation because:
rem    * the pipe ACL only admits elevated processes;
rem    * ESurfingSvr is a LocalSystem DEMAND_START service.
rem
rem  IMPORTANT: the named pipe is SINGLE INSTANCE, so if the official client GUI
rem  is running it holds the pipe and this will simply yield to it (and say so).
rem  That is by design - use this when the client is NOT running.
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\src\TianyicampusDialer.ps1" -Once
echo.
echo Exit code: %errorlevel%   (0 = ok/authenticated, 2 = dial did not succeed, 3 = no credential)
echo.
pause