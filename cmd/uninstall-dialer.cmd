@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Remove the no-GUI dialer scheduled task (TianyicampusDialer).
rem  Does NOT touch the official client, the service, the registry or anything
rem  else - it only unregisters the task this project created.
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\src\TianyicampusDialer.ps1" -Uninstall
echo.
echo Exit code: %errorlevel%   (0 = removed)
echo.
pause