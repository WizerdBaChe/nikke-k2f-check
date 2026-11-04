@echo off
rem Double-click to check this PC. Read-only unless you answer Y twice. Source: https://github.com/WizerdBaChe/nikke-k2f-check
rem Add "check" to only check: Run-Check.cmd check
setlocal
set "K2F_MODE="
if /i "%~1"=="check" set "K2F_MODE=-CheckOnly"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-K2F.ps1" %K2F_MODE%
exit /b %errorlevel%
