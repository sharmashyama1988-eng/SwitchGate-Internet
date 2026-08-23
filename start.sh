#!/usr/bin/env bash
# SwitchGate 1-Click Runner for Linux & Raspberry Pi
cd "$(dirname "$0")"

echo "==================================================="
echo "  SwitchGate: No-Code Network Gateway & Remote Control"
echo "==================================================="
echo ""
echo "[*] Ensuring Python environment..."
python3 -m pip install -r requirements.txt --quiet

echo "[*] Launching SwitchGate (Root/Sudo recommended for raw packet control)..."
if [ "$EUID" -ne 0 ]; then
    echo "[!] Tip: Run with 'sudo ./start.sh' for 100% ARP spoofing & raw firewall power."
fi

python3 run.py
