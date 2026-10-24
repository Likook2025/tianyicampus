@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  End-to-end test: log in through the background service ONLY (no GUI, no
rem  clicking at all), using the credentials file the official client keeps at
rem  %APPDATA%\ChinatelecomJSPortal\Config\config.xml
rem
rem  Requires elevation (the pipe ACL only admits elevated processes).
rem
rem  BEFORE running: exit the client from the tray so the single pipe instance
rem  is free. A graceful exit makes the client send PortalDisConnect, so the
rem  network WILL drop - this script then tries to bring it back up by itself.
rem  If it fails, just reopen the client and click login as usual.
rem
rem  Report: logs\login-trial-<stamp>.txt
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation (one UAC prompt)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tools\Try-PortalLogin.ps1"
echo.
echo If the report says it failed, reopen the client and click login to restore
echo the network, then hand the report back to the agent.
echo.
pause