@echo off
title SwitchGate Turbo Build & Packager (20s)
cd /d "%~dp0"
echo ===================================================
echo   SwitchGate Turbo Packager (SSD Accelerated)
echo ===================================================
echo.
python fast_package.py
pause
