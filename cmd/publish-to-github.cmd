@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem ============================================================================
rem  Publish this repository to GitHub.
rem
rem  The repository is already initialised and committed locally
rem  (branch "main", 61 files, no secrets). This script finishes the job:
rem
rem    1) fix the commit author (the local commit used a placeholder identity)
rem    2) point "origin" at your GitHub repository
rem    3) push
rem
rem  Before running, create an EMPTY repository on GitHub (no README, no
rem  .gitignore - otherwise the first push conflicts).
rem
rem  Usage:
rem    publish-to-github.cmd  https://github.com/<you>/<repo>.git
rem    publish-to-github.cmd                      (will prompt for the URL)
rem
rem  Authentication is handled by Git Credential Manager: a browser/sign-in
rem  window will appear the first time. Use a personal access token if asked
rem  for a password.
rem
rem  Keep this file PURE ASCII (cmd.exe parses .cmd as ANSI/GBK).
rem ============================================================================

cd /d "%~dp0.."

echo ============================================================
echo  Publish to GitHub
echo  Repository: %CD%
echo ============================================================
echo.

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
  echo [X] This folder is not a git repository. Nothing to do.
  goto :end
)

rem ---- 0. make sure there is nothing uncommitted that we would silently skip
for /f "delims=" %%s in ('git status --porcelain') do (
  echo [!] You have uncommitted changes. Publishing anyway, but they will NOT
  echo     be included. Commit them first if that was not intended.
  echo.
  goto :identity
)

:identity
echo --- Step 1/3: commit author ---
for /f "delims=" %%i in ('git config user.name')  do set "CURNAME=%%i"
for /f "delims=" %%i in ('git config user.email') do set "CURMAIL=%%i"
echo     current: "!CURNAME!" ^<!CURMAIL!^>
echo     (the local commit used a placeholder; enter your real ones so the
echo      commit is attributed to you)
echo.
set "NEWNAME="
set /p "NEWNAME=Your name  [Enter = keep]: "
if not "!NEWNAME!"=="" git config user.name "!NEWNAME!"
set "NEWMAIL="
set /p "NEWMAIL=Your email [Enter = keep]: "
if not "!NEWMAIL!"=="" git config user.email "!NEWMAIL!"
git commit --amend --reset-author --no-edit >nul 2>&1
echo     commit author is now:
git log -1 --format="      %%an <%%ae>"
echo.

echo --- Step 2/3: remote ---
set "URL=%~1"
if "!URL!"=="" set /p "URL=GitHub repository URL (https://github.com/USER/REPO.git): "
if "!URL!"=="" (
  echo [X] No URL given. Aborting.
  goto :end
)
git remote remove origin >nul 2>&1
git remote add origin "!URL!"
git remote -v
echo.

echo --- Step 3/3: push ---
git branch -M main
git push -u origin main
if errorlevel 1 (
  echo.
  echo [X] Push failed. Common causes:
  echo     - the GitHub repository is not empty (it must be created EMPTY)
  echo     - not signed in yet (let Git Credential Manager open its window)
  echo     - wrong URL / no write permission
  goto :end
)
echo.
echo [OK] Pushed. Open: !URL!

:end
echo.
pause