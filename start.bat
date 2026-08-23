@echo off
title SwitchGate - Network Gateway Controller
cd /d "%~dp0"

:: Auto-Elevation Check (Requests Administrator Privileges)
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo ===================================================
    echo [*] Requesting Administrator Privileges for Firewall ^& Kernel Network Control...
    echo ===================================================
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo   SwitchGate: No-Code Network Gateway ^& Remote Control v2.0
echo   [100% Kernel Firewall Privileges Active]
echo ===================================================
echo.
echo [*] Checking Python dependencies...
python -m pip install -r requirements.txt --quiet
echo [*] Launching SwitchGate Gateway...
python run.py
pause
