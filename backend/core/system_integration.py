"""
SwitchGate - Windows System Integration & Auto-Start Controller
Manages Windows Registry Startup (Run key), Desktop Shortcuts, and System Tray integration.
"""
import os
import sys
import platform
from pathlib import Path
from backend.database import db

class SystemIntegration:
    REG_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_REG_NAME = "SwitchGateGateway"

    @classmethod
    def is_windows(cls) -> bool:
        return platform.system() == "Windows"

    @classmethod
    def set_run_on_startup(cls, enable: bool) -> bool:
        """Adds or removes SwitchGate from Windows Startup registry."""
        if not cls.is_windows():
            return False

        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY_PATH, 0, winreg.KEY_SET_VALUE)
            if enable:
                executable_path = sys.executable
                if getattr(sys, 'frozen', False):
                    cmd = f'"{sys.executable}"'
                else:
                    script_path = Path(__file__).resolve().parent.parent.parent / "desktop_app.py"
                    cmd = f'"{executable_path}" "{script_path}"'
                winreg.SetValueEx(key, cls.APP_REG_NAME, 0, winreg.REG_SZ, cmd)
                print(f"[System] Registered startup command: {cmd}")
            else:
                try:
                    winreg.DeleteValue(key, cls.APP_REG_NAME)
                    print("[System] Removed SwitchGate from Windows startup.")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            db.set_setting("run_on_startup", "1" if enable else "0")
            return True
        except Exception as e:
            print(f"[System Integration Error] {e}")
            return False

    @classmethod
    def get_startup_status(cls) -> bool:
        if not cls.is_windows():
            return False
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY_PATH, 0, winreg.KEY_READ)
            try:
                val, _ = winreg.QueryValueEx(key, cls.APP_REG_NAME)
                winreg.CloseKey(key)
                return bool(val)
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        except Exception:
            return False

system_integration = SystemIntegration()
