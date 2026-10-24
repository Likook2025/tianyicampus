@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Install the no-GUI dialer. This is the ONE thing you need to run.
rem
rem  It does two things:
rem    1) if no credential is stored yet, it asks for your campus account and
rem       password and saves them DPAPI-encrypted (dial.secrets.json, gitignored);
rem       your password is never written in plaintext and never leaves this PC;
rem    2) registers a scheduled task:
rem         trigger : at logon (current user)
rem         run as  : highest privileges -> NO UAC prompt, and it can start the
rem                   LocalSystem service ESurfingSvr
rem         action  : powershell -File src\TianyicampusDialer.ps1 -Watch
rem
rem  After that, logging in to Windows is all it takes.
rem  Update the password later : cmd\setup-dialer-credential.cmd
rem  Remove everything         : cmd\uninstall-dialer.cmd
rem
rem  Keep this file PURE ASCII (cmd.exe parses .cmd as ANSI/GBK).
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation (one UAC prompt, only this once)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
if exist "%~dp0..\dial.secrets.json" goto install

echo.
echo [Tianyicampus] Step 1/2: no credential stored yet - let's set it up.
echo   (account + password, saved DPAPI-encrypted; only this PC + this Windows
echo    account can decrypt it, and it is gitignored)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tools\Set-DialerCredential.ps1"
if errorlevel 1 (
  echo.
  echo Credential setup did not complete. Nothing was installed.
  echo Re-run this file when you are ready.
  echo.
  pause
  exit /b 1
)
echo.
echo [Tianyicampus] Step 2/2: registering the logon task.
goto install_go

:install
echo.
echo [Tianyicampus] A credential is already stored - skipping the login step.
echo   (to change it, run cmd\setup-dialer-credential.cmd)

:install_go
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\src\TianyicampusDialer.ps1" -Install
echo.
echo Exit code: %errorlevel%   (0 = installed)
echo.
echo Done. From now on the campus network is authenticated automatically at logon,
echo with no window and no clicking.
echo.
pause