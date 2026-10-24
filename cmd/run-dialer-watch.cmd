@echo off
chcp 65001 >nul
setlocal

rem ============================================================================
rem  Start the dialer in WATCH mode in the foreground, for testing.
rem
rem  This is the exact same code path the logon scheduled task runs, so it is
rem  the honest way to verify the loop. It should print:
rem      "started service ... keep.cgi"        (if the service was stopped)
rem      "single-instance lock acquired ... entering watch loop"
rem  and then KEEP RUNNING (one round every PollIntervalIdle/Campus seconds).
rem
rem  If it instead says an instance is already running while nothing else is,
rem  the single-instance lock handling is broken.
rem
rem  Close this window (or Ctrl+C) to stop it.
rem
rem  ---------------------------------------------------------------------------
rem  IMPORTANT for maintainers: keep this file PURE ASCII.
rem  cmd.exe parses .cmd files using the ANSI code page (GBK here) regardless of
rem  "chcp 65001" (that only affects console output, not parsing). UTF-8 Chinese
rem  in a .cmd therefore gets mis-decoded, and a mangled byte can swallow a quote
rem  or a line break -- an unterminated quote then makes cmd.exe eat the
rem  following lines, including the elevation logic, and the window just flashes
rem  and exits. That is exactly the bug this file used to have.
rem ============================================================================

if defined GUARD_ELEVATED goto payload
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
if not errorlevel 1 goto payload
echo [Tianyicampus] Requesting elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:GUARD_ELEVATED='1'; $env:GUARD_SELF='%~f0'; try { Start-Process -FilePath $env:GUARD_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message); Start-Sleep -Seconds 8 }"
exit /b 0

:payload
echo [Tianyicampus] Watch mode. Close this window to stop.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\src\TianyicampusDialer.ps1" -Watch
echo.
echo Watch loop ended (exit code %errorlevel%).
pause