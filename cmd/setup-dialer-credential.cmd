@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Enter / update the campus account + password, stored DPAPI-encrypted.
rem
rem  No elevation needed: the secret is protected with DPAPI under YOUR user, and
rem  the file lives inside the project folder (dial.secrets.json, gitignored).
rem
rem  Usage:
rem    setup-dialer-credential.cmd            -> enter / update
rem    setup-dialer-credential.cmd /show      -> show which account is stored
rem    setup-dialer-credential.cmd /remove    -> delete the stored credential
rem
rem  Keep this file PURE ASCII (cmd.exe parses .cmd as ANSI/GBK).
rem ============================================================================

set "SCRIPT=%~dp0..\tools\Set-DialerCredential.ps1"
set "ARGS="
if /i "%~1"=="/show"   set "ARGS=-Show"
if /i "%~1"=="/remove" set "ARGS=-Remove"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %ARGS%
echo.
pause