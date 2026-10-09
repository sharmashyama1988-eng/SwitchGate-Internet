# SwitchGate Internet - PowerShell Modern Launcher
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Check Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsPrincipal][Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[*] Requesting Administrator Privileges for SwitchGate..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = "SwitchGate Internet v2.0 - Cyber Gateway"

# Find Python
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    $pythonExe = (Get-Command py -ErrorAction SilentlyContinue).Source
}
if (-not $pythonExe) {
    $candidates = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue
    if ($candidates) { $pythonExe = $candidates[0].FullName }
}

if (-not $pythonExe) {
    Write-Host "[ERROR] Python 3.10+ not found in system PATH." -ForegroundColor Red
    Write-Host "Please download from https://www.python.org/ and check 'Add Python to PATH'." -ForegroundColor Yellow
    pause
    exit 1
}

Clear-Host
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "   SWITCHGATE INTERNET v2.0 - CYBER GATEWAY CONTROLLER" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host " Python Engine: $pythonExe" -ForegroundColor Gray
Write-Host " Working Dir  : $ScriptDir" -ForegroundColor Gray
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Starting SwitchGate..." -ForegroundColor Green
Write-Host ""

& $pythonExe run.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[!] Exited with code $LASTEXITCODE." -ForegroundColor Red
    pause
}
