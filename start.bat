@echo off
title SwitchGate - Network Gateway Controller v2.5
cd /d "%~dp0"

:: Auto-Elevation Check (Requests Administrator Privileges once)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ===================================================
    echo [*] Requesting Administrator Privileges for Windows Firewall ^& Network Control...
    echo ===================================================
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo   SwitchGate v2.5 - 100%% Real Kernel Network Controller
echo   [Full Administrator Privileges Active]
echo ===================================================
echo.

if exist "desktop_app.py" (
    python desktop_app.py
) else (
    python run.py
)
pause
