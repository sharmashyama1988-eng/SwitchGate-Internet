@echo off
title Build SwitchGate Executable
cd /d "%~dp0"
echo ===================================================
echo   Compiling SwitchGate to Windows Standalone (.EXE)
echo ===================================================
echo.
python build_exe.py
pause
