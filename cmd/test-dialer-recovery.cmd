@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Verify the RUNNING guard can heal the network by itself.
rem
rem  This script only "kicks once": it sends PortalDisConnect to drop the
rem  session, then does NOTHING but watch. Recovery must come from the guard
rem  that is already running in watch mode - otherwise the test would prove
rem  nothing.
rem
rem  Preconditions:
rem    * the guard is running: cmd\run-dialer-watch.cmd window still open;
rem    * the official client is NOT running (the pipe must be free);
rem    * elevation (the pipe ACL only admits elevated processes).
rem
rem  Up to ~2 minutes may pass before the guard's next round (it polls every
rem  PollIntervalIdle=120s while authenticated).
rem
rem  Report: logs\recovery-<stamp>.txt
rem
rem  Keep this file PURE ASCII (cmd.exe parses .cmd as ANSI/GBK).
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tools\Test-DialerRecovery.ps1"
echo.
pause