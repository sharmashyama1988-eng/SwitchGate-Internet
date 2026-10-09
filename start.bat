@echo off
setlocal

cd /d "%~dp0"

REM 1. Find Python executable
set "PY_EXE="
where python >nul 2>&1 && set "PY_EXE=python"
if not defined PY_EXE (
    where py >nul 2>&1 && set "PY_EXE=py"
)
if not defined PY_EXE (
    for /d %%i in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%i\python.exe" set "PY_EXE=%%i\python.exe"
    )
)

if not defined PY_EXE (
    echo [ERROR] Python not found in PATH or default install directory.
    echo Please make sure Python 3.10+ is installed from https://www.python.org/
    echo and that "Add Python to PATH" was checked during installation.
    echo.
    pause
    exit /b 1
)

REM 2. Check for Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ==============================================================
    echo  SwitchGate requires Administrator Privileges for ARP & Firewall.
    echo  Requesting UAC Elevation...
    echo ==============================================================
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title SwitchGate Internet v2.0 - Cyber Gateway

cls
echo ==============================================================
echo   SWITCHGATE INTERNET v2.0 - CYBER GATEWAY CONTROLLER
echo ==============================================================
echo   Python Engine: %PY_EXE%
echo   Working Directory: %~dp0
echo ==============================================================
echo.
echo [*] Launching SwitchGate...
echo.

"%PY_EXE%" run.py

if %errorlevel% neq 0 (
    echo.
    echo [!] SwitchGate stopped with exit code %errorlevel%.
    pause
)
