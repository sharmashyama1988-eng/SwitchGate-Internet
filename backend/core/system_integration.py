"""
SwitchGate - Windows System Integration & Auto-Start Controller v2.1
Manages Windows Task Scheduler (primary), Registry Run key (fallback),
Desktop Shortcuts, and System Tray integration.
Zero admin required — all methods use HKCU or user-level Task Scheduler.
"""
import os
import sys
import platform
import subprocess
from pathlib import Path
from backend.database import db
from backend.core.silent_process import silent_run


class SystemIntegration:
    REG_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_REG_NAME  = "SwitchGateGateway"
    TASK_NAME     = "SwitchGateAutoStart"

    @classmethod
    def is_windows(cls) -> bool:
        return platform.system() == "Windows"

    @classmethod
    def _get_launch_cmd(cls) -> str:
        """Builds the correct launch command for both frozen EXE and Python script modes."""
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}"'
        else:
            script_dir = Path(__file__).resolve().parent.parent.parent
            # Prefer desktop_app.py (native window), fallback to run.py (browser mode)
            for candidate in ("desktop_app.py", "run.py"):
                p = script_dir / candidate
                if p.exists():
                    return f'"{sys.executable}" "{p}"'
            return f'"{sys.executable}"'

    # ─────────────────────────────────────────────────────────────────────────
    # Primary: Task Scheduler (Highest Privileges, No UAC)
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _set_task_scheduler(cls, enable: bool) -> bool:
        """
        Creates/removes a Task Scheduler entry with HIGHEST run level.
        This gives the app admin-equivalent powers on launch with ZERO UAC popup.
        Works for users in the Administrators group.
        """
        if not cls.is_windows():
            return False
        try:
            if enable:
                cmd = cls._get_launch_cmd()
                schtasks_args = [
                    "schtasks", "/create",
                    "/tn", cls.TASK_NAME,
                    "/tr", cmd,
                    "/sc", "ONLOGON",
                    "/rl", "HIGHEST",
                    "/delay", "0000:08",
                    "/it", "/f"
                ]
                r = silent_run(schtasks_args, capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    print(f"[System] ✅ Task Scheduler entry '{cls.TASK_NAME}' created (HIGHEST privileges).")
                    return True
                # Retry without /rl HIGHEST for standard users
                schtasks_basic = [
                    "schtasks", "/create",
                    "/tn", cls.TASK_NAME,
                    "/tr", cmd,
                    "/sc", "ONLOGON",
                    "/delay", "0000:08",
                    "/it", "/f"
                ]
                r2 = silent_run(schtasks_basic, capture_output=True, text=True, timeout=10)
                if r2.returncode == 0:
                    print(f"[System] ✅ Task Scheduler entry '{cls.TASK_NAME}' created (standard mode).")
                    return True
                return False
            else:
                r = silent_run(
                    ["schtasks", "/delete", "/tn", cls.TASK_NAME, "/f"],
                    capture_output=True, text=True, timeout=10
                )
                return r.returncode == 0
        except Exception as e:
            print(f"[System] Task Scheduler error: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Fallback: HKCU Registry Run Key (Always works, no admin needed)
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _set_registry_run(cls, enable: bool) -> bool:
        """HKCU registry run key — always writable without admin."""
        if not cls.is_windows():
            return False
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                cls.REG_KEY_PATH, 0,
                winreg.KEY_SET_VALUE
            )
            if enable:
                cmd = cls._get_launch_cmd()
                winreg.SetValueEx(key, cls.APP_REG_NAME, 0, winreg.REG_SZ, cmd)
                print(f"[System] Registry startup registered: {cmd}")
            else:
                try:
                    winreg.DeleteValue(key, cls.APP_REG_NAME)
                    print("[System] Removed SwitchGate from Windows startup registry.")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"[System Integration Error] {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def set_run_on_startup(cls, enable: bool) -> bool:
        """
        Enables/disables auto-start using the best available method.
        Priority: Task Scheduler (no UAC) > Registry Run key (fallback).
        """
        # Try Task Scheduler first (gives highest privileges without UAC popup)
        success = cls._set_task_scheduler(enable)
        if not success:
            # Fallback to HKCU registry (always works, standard user safe)
            success = cls._set_registry_run(enable)

        db.set_setting("run_on_startup", "1" if enable else "0")
        return success

    @classmethod
    def get_startup_status(cls) -> bool:
        """Returns True if auto-start is configured via either method."""
        if not cls.is_windows():
            return False

        # Check Task Scheduler first
        try:
            r = silent_run(
                ["schtasks", "/query", "/tn", cls.TASK_NAME, "/fo", "LIST"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0 and cls.TASK_NAME in r.stdout:
                return True
        except Exception:
            pass

        # Check Registry fallback
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                cls.REG_KEY_PATH, 0,
                winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, cls.APP_REG_NAME)
                winreg.CloseKey(key)
                return bool(val)
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        except Exception:
            return False

    @classmethod
    def create_desktop_shortcut(cls) -> bool:
        """Creates a desktop shortcut for SwitchGate (no admin needed)."""
        if not cls.is_windows():
            return False
        try:
            import winreg
            # Get Desktop path from registry
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                0, winreg.KEY_READ
            )
            desktop_path, _ = winreg.QueryValueEx(key, "Desktop")
            winreg.CloseKey(key)

            shortcut_path = Path(desktop_path) / "SwitchGate.lnk"
            cmd = cls._get_launch_cmd()

            # Create shortcut via PowerShell (no COM/pythonwin needed)
            ps_script = f"""
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut('{shortcut_path}')
$Shortcut.TargetPath = {cmd.split()[0].strip('"')}
$Shortcut.Description = 'SwitchGate Network Gateway Controller'
$Shortcut.WorkingDirectory = '{Path(__file__).resolve().parent.parent.parent}'
$Shortcut.Save()
"""
            silent_run(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
                capture_output=True, timeout=10
            )
            print(f"[System] Desktop shortcut created: {shortcut_path}")
            return True
        except Exception as e:
            print(f"[System] Shortcut creation notice: {e}")
            return False


system_integration = SystemIntegration()
