"""
SwitchGate - Universal Launcher & Environment Orchestrator
Auto-elevates to Administrator once on startup on Windows so no repetitive permissions are prompted.
"""
import os
import sys
import time
import socket
import logging
import warnings
import webbrowser
import threading

# Suppress Scapy "No libpcap" warnings BEFORE any backend import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*libpcap.*")
warnings.filterwarnings("ignore", message=".*pcap.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, module="scapy")

import uvicorn

from backend.config import AppConfig

def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def elevate_if_needed():
    """Requests Administrator elevation once on Windows launch."""
    if os.name == "nt" and not is_admin():
        # Check if already attempted or launched via arg
        if "--no-elevate" not in sys.argv:
            try:
                import ctypes
                params = " ".join([f'"{arg}"' for arg in sys.argv] + ["--no-elevate"])
                print("[*] Requesting One-Time Administrator Privileges for Firewall & Raw Packet Control...")
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                if ret > 32:
                    sys.exit(0)
            except Exception as e:
                print(f"[!] Elevation notice: {e}")

def open_browser_delayed(url: str, delay: float = 1.2):
    def _open():
        time.sleep(delay)
        print(f"[SwitchGate] Opening dashboard at {url}")
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()

def main():
    elevate_if_needed()

    print(r"""
   _____         _ _       _     _____       _       
  / ____|       (_) |     | |   / ____|     | |      
 | (_____      ___| |_ ___| |__| |  __  __ _| |_ ___ 
  \___ \ \ /\ / / | __/ __| '_ \ | |_ |/ _` | __/ _ \
  ____) \ V  V /| | || (__| | | | |__| | (_| | ||  __/
 |_____/ \_/\_/ |_|\__\___|_| |_|\_____|\__,_|\__\___|
       No-Code Network Gateway & Remote Control v2.0
    """)

    admin_status = "YES (Full Admin Privileges Granted)" if is_admin() else "STANDARD USER (Safe Mode Active)"
    print(f"[*] Platform: {sys.platform.title()} | Admin Privileges: {admin_status}")
    print(f"[*] Detected Local IP: {AppConfig.LOCAL_IP}")
    print(f"[*] Detected Gateway:  {AppConfig.GATEWAY_IP}")
    print(f"[*] Network CIDR:      {AppConfig.NETWORK_CIDR}")
    print(f"[*] Interface:         {AppConfig.INTERFACE_NAME or 'Default Adapter'}")
    print(f"[*] Web Dashboard:     http://localhost:{AppConfig.PORT}\n")

    open_browser_delayed(f"http://localhost:{AppConfig.PORT}")

    uvicorn.run(
        "backend.main:app",
        host=AppConfig.HOST,
        port=AppConfig.PORT,
        log_level="info" if AppConfig.DEBUG else "warning",
        reload=False
    )

if __name__ == "__main__":
    main()
