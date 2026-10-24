@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Determine the wire format of the ESurfingSvr named pipe.
rem
rem  Requires elevation (the pipe ACL only admits elevated processes, because the
rem  official GUI itself is elevated).
rem
rem  BEFORE running: exit the client from the tray (right-click -> exit), so the
rem  single pipe instance is free. NOTE: a graceful exit makes the client send
rem  PortalDisConnect, so your network WILL drop until you log in again.
rem
rem  Results go to logs\pipe-wire-<stamp>.txt (self-contained; survives a
rem  network outage).
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation (one UAC prompt)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tools\Probe-PortalPipeWire.ps1"
echo.
pause