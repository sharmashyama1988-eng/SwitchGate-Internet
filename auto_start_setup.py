"""
SwitchGate - Auto-Start Setup (Task Scheduler Method)
Sets up Windows Task Scheduler to run SwitchGate at login with HIGHEST privileges
WITHOUT showing a UAC prompt every time.

Run this ONCE to configure auto-start:
    python auto_start_setup.py

After this, SwitchGate will open automatically on every Windows login
with full admin-equivalent privileges and ZERO UAC popup.
"""
import os
import sys
import platform
import subprocess
from pathlib import Path


def setup_task_scheduler_autostart(enable: bool = True) -> bool:
    """
    Creates/removes a Windows Task Scheduler entry that runs SwitchGate
    at user logon with 'HIGHEST' run level — full privileges, NO UAC prompt.
    """
    if platform.system() != "Windows":
        print("[AutoStart] Task Scheduler is Windows-only. Skipping.")
        return False

    task_name = "SwitchGateAutoStart"
    script_dir = Path(__file__).resolve().parent

    # Determine the correct executable command
    if getattr(sys, 'frozen', False):
        # Running as compiled .exe
        exe_path = sys.executable
        cmd = f'"{exe_path}"'
        working_dir = str(Path(exe_path).parent)
    else:
        # Running as Python script
        python_exe = sys.executable
        script_path = script_dir / "desktop_app.py"
        if not script_path.exists():
            script_path = script_dir / "run.py"
        cmd = f'"{python_exe}" "{script_path}"'
        working_dir = str(script_dir)

    if enable:
        print(f"[AutoStart] Registering Task Scheduler entry: {task_name}")
        print(f"[AutoStart] Command: {cmd}")
        print(f"[AutoStart] Working Dir: {working_dir}")

        # Build schtasks command:
        # /RL HIGHEST = run with highest available privileges (no UAC popup on launch)
        # /SC ONLOGON = trigger on user login
        # /DELAY 0000:10 = 10 second delay after login
        # /F = force overwrite existing
        schtasks_cmd = [
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", cmd,
            "/sc", "ONLOGON",
            "/rl", "HIGHEST",
            "/delay", "0000:10",
            "/it",               # interactive (show window)
            "/f",                # force overwrite
        ]

        try:
            result = subprocess.run(
                schtasks_cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                print(f"[AutoStart] ✅ Task '{task_name}' registered successfully!")
                print("[AutoStart] SwitchGate will now auto-start on login with ZERO UAC popup.")
                return True
            else:
                # Try without /RL HIGHEST (standard user fallback)
                schtasks_cmd_basic = [
                    "schtasks", "/create",
                    "/tn", task_name,
                    "/tr", cmd,
                    "/sc", "ONLOGON",
                    "/delay", "0000:10",
                    "/it",
                    "/f"
                ]
                result2 = subprocess.run(
                    schtasks_cmd_basic,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result2.returncode == 0:
                    print(f"[AutoStart] ✅ Task '{task_name}' registered (standard user mode).")
                    return True
                else:
                    print(f"[AutoStart] schtasks error: {result.stderr.strip()}")
                    # Fallback: Use Windows Registry Run key (HKCU — no admin needed)
                    return _registry_fallback(enable, cmd)
        except Exception as e:
            print(f"[AutoStart] Task Scheduler exception: {e}")
            return _registry_fallback(enable, cmd)

    else:
        # Delete the task
        try:
            result = subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True, text=True, timeout=10
            )
            print(f"[AutoStart] Task '{task_name}' removed.")
            _registry_fallback(False, "")
            return True
        except Exception as e:
            print(f"[AutoStart] Remove error: {e}")
            return False


def _registry_fallback(enable: bool, cmd: str) -> bool:
    """
    Fallback: Windows Registry HKCU Run key.
    This NEVER requires admin — HKCU is always writable by current user.
    """
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "SwitchGateGateway"

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_READ
        )

        if enable:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
            print(f"[AutoStart] ✅ Registry fallback set: HKCU\\...\\Run\\{app_name}")
            print(f"[AutoStart] Command: {cmd}")
        else:
            try:
                winreg.DeleteValue(key, app_name)
                print(f"[AutoStart] Registry entry '{app_name}' removed.")
            except FileNotFoundError:
                pass

        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"[AutoStart] Registry fallback error: {e}")
        return False


def check_status() -> dict:
    """Returns current auto-start status from both Task Scheduler and Registry."""
    status = {"task_scheduler": False, "registry": False, "task_name": "SwitchGateAutoStart"}

    # Check Task Scheduler
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", "SwitchGateAutoStart", "/fo", "LIST"],
            capture_output=True, text=True, timeout=5
        )
        status["task_scheduler"] = result.returncode == 0
    except Exception:
        pass

    # Check Registry
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_READ
        )
        try:
            val, _ = winreg.QueryValueEx(key, "SwitchGateGateway")
            status["registry"] = bool(val)
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass

    return status


if __name__ == "__main__":
    print("=" * 55)
    print("  SwitchGate — Auto-Start Setup (Zero UAC)")
    print("=" * 55)
    print()

    import argparse
    parser = argparse.ArgumentParser(description="SwitchGate Auto-Start Setup")
    parser.add_argument("--disable", action="store_true", help="Remove auto-start entry")
    parser.add_argument("--status", action="store_true", help="Check current auto-start status")
    args = parser.parse_args()

    if args.status:
        s = check_status()
        print(f"Task Scheduler: {'✅ Active' if s['task_scheduler'] else '❌ Not set'}")
        print(f"Registry Run:   {'✅ Active' if s['registry'] else '❌ Not set'}")
    elif args.disable:
        setup_task_scheduler_autostart(enable=False)
        print("\n✅ Auto-start disabled. SwitchGate will NOT open on login.")
    else:
        success = setup_task_scheduler_autostart(enable=True)
        if success:
            print("\n✅ Done! SwitchGate will auto-start on next login.")
            print("   No admin popup. No UAC. Just opens silently.")
        else:
            print("\n⚠️  Setup had issues. Try running as administrator once.")
