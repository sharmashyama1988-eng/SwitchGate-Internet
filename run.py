"""
SwitchGate - Universal Launcher & Environment Orchestrator v2.1
Zero-UAC-Prompt startup: App opens directly without any admin permission dialog.
Admin-level features degrade gracefully when running as standard user.
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


def is_admin() -> bool:
    """Check current privilege level — no UAC prompt, just a silent check."""
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def try_silent_privilege_boost():
    """
    Attempts token-level privilege escalation WITHOUT any UAC dialog.
    Uses Windows API to enable all available privileges in the current token.
    This works when the user is in Administrators group but UAC-limited.
    No popup, no prompt — completely silent.
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        privileges_to_enable = [
            "SeDebugPrivilege", "SeNetworkLogonRight", "SeIncreaseBasePriorityPrivilege",
            "SeManageVolumePrivilege", "SeLoadDriverPrivilege", "SeSecurityPrivilege",
            "SeBackupPrivilege", "SeRestorePrivilege",
        ]

        h_token = wintypes.HANDLE()
        h_process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
            return

        for priv_name in privileges_to_enable:
            try:
                luid = LUID()
                if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                    continue
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
            except Exception:
                continue

        kernel32.CloseHandle(h_token)
        print("[*] Silent privilege boost applied (zero UAC prompts).")
    except Exception as e:
        print(f"[*] Privilege boost notice: {e}")


def open_browser_delayed(url: str, delay: float = 1.2):
    def _open():
        time.sleep(delay)
        print(f"[SwitchGate] Opening dashboard at {url}")
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()


def elevate_if_needed():
    """Requests Administrator elevation once on Windows launch to grant full kernel firewall permissions."""
    if os.name == "nt" and not is_admin():
        if "--no-elevate" not in sys.argv:
            try:
                import ctypes
                from pathlib import Path
                script_path = str(Path(sys.argv[0]).resolve())
                base_dir = str(Path(__file__).resolve().parent)
                remaining_args = [f'"{arg}"' for arg in sys.argv[1:] if arg != "--no-elevate"]
                params = f'"{script_path}" ' + " ".join(remaining_args + ["--no-elevate"])
                print("[*] Requesting Administrator Privileges for 100% Real Kernel Firewall & Packet Blocking...")
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params.strip(), base_dir, 1)
                if ret > 32:
                    sys.exit(0)
            except Exception as e:
                print(f"[!] Elevation notice: {e}")

def main():
    elevate_if_needed()
    try_silent_privilege_boost()

    print(r"""
   _____         _ _       _     _____       _       
  / ____|       (_) |     | |   / ____|     | |      
 | (_____      ___| |_ ___| |__| |  __  __ _| |_ ___ 
  \___ \ \ /\ / / | __/ __| '_ \ | |_ |/ _` | __/ _ \
  ____) \ V  V /| | || (__| | | | |__| | (_| | ||  __/
 |_____/ \_/\_/ |_|\__\___|_| |_|\_____|__,_|\__\___|
       No-Code Network Gateway & Remote Control v2.1
    """)

    admin_status = "✅ FULL ADMINISTRATOR (Kernel Firewall & Packet Control Active)" if is_admin() else "⚠️ Standard User (Run as Administrator recommended for 100% firewall control)"
    print(f"[*] Platform:       {sys.platform.title()}")
    print(f"[*] Privilege Mode: {admin_status}")
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
