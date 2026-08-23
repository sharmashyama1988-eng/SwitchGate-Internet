"""
SwitchGate - Zero-Boot-Impact Windows Startup Manager
Registers background startup with delayed execution (IDLE priority) to ensure 0% Windows boot slowdown.
"""
import os
import sys
import platform
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    import winreg
    _RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

class WindowsStartupManager:
    APP_NAME = "SwitchGateNetworkController"

    @classmethod
    def enable_startup(cls, delayed_seconds: int = 10) -> bool:
        """
        Enables non-blocking background startup.
        Uses delayed execution so Windows desktop and explorer load instantly with 0ms boot delay.
        """
        if not IS_WINDOWS:
            return False
        try:
            # Resolve executable / pythonw path
            python_exe = sys.executable
            # If python.exe, prefer pythonw.exe for windowless background startup
            pythonw = Path(python_exe).parent / "pythonw.exe"
            if pythonw.exists():
                runner = str(pythonw)
            else:
                runner = str(python_exe)

            run_py = Path(__file__).resolve().parent.parent.parent / "run.py"
            # Launch command with delayed safe boot flag
            cmd = f'"{runner}" "{run_py}" --startup --delay {delayed_seconds}'

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
            print(f"[Startup Manager] Zero-Boot-Impact Startup Enabled ({cmd}).")
            return True
        except Exception as e:
            print(f"[Startup Manager] Error enabling startup: {e}")
            return False

    @classmethod
    def disable_startup(cls) -> bool:
        """Removes SwitchGate from Windows startup."""
        if not IS_WINDOWS:
            return False
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, cls.APP_NAME)
            winreg.CloseKey(key)
            print("[Startup Manager] Startup Disabled.")
            return True
        except FileNotFoundError:
            return True
        except Exception as e:
            print(f"[Startup Manager] Error disabling startup: {e}")
            return False

    @classmethod
    def is_enabled(cls) -> bool:
        if not IS_WINDOWS:
            return False
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, cls.APP_NAME)
            winreg.CloseKey(key)
            return bool(val)
        except Exception:
            return False

startup_manager = WindowsStartupManager()
