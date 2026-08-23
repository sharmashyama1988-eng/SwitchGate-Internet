"""
SwitchGate - Clean Rebuild & Output Manager
Completely wipes old build artifacts and compiles fresh, clean SwitchGate.exe standalone desktop application.
"""
import os
import sys
import time
import shutil
import tempfile
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def clean():
    print("==================================================")
    print("   🧹 CLEANING OLD SWITCHGATE BUILDS & TEMPS      ")
    print("==================================================")

    # 1. Kill old running instances
    if os.name == "nt":
        subprocess.run("taskkill /f /im SwitchGate.exe", shell=True, capture_output=True)

    time.sleep(1.0)

    # 2. Remove directories on workspace (F:) and SSD (C:)
    for folder_name in ["build", "dist", "MSIX_Package_Source"]:
        p = BASE_DIR / folder_name
        if p.exists():
            try:
                shutil.rmtree(p, ignore_errors=True)
                print(f"[+] Removed old directory: {p.name}")
            except Exception as e:
                print(f"[!] Warning removing {p.name}: {e}")

    ssd_temp = Path(os.environ.get("TEMP", tempfile.gettempdir())) / "SwitchGate_SSD_Build"
    if ssd_temp.exists():
        try:
            shutil.rmtree(ssd_temp, ignore_errors=True)
            print("[+] Cleaned SSD temp folder")
        except Exception:
            pass

    static_ssd = Path(r"C:\Users\Amit\AppData\Local\Temp\SwitchGate_SSD_Build")
    if static_ssd.exists():
        try:
            shutil.rmtree(static_ssd, ignore_errors=True)
        except Exception:
            pass

    # Remove old spec files
    for spec in BASE_DIR.glob("*.spec"):
        try:
            spec.unlink()
            print(f"[+] Removed spec file: {spec.name}")
        except Exception:
            pass

    print("[✅] Cleanup complete!")

def rebuild_all():
    clean()

    print("\n==================================================")
    print("   🚀 COMPILING FRESH CLEAN SWITCHGATE.EXE         ")
    print("==================================================")

    import build_exe
    success = build_exe.build()

    if success:
        import prepare_msix_folder
        prepare_msix_folder.prepare_staging()

        exe_file = BASE_DIR / "dist" / "SwitchGate" / "SwitchGate.exe"
        staging_dir = BASE_DIR / "MSIX_Package_Source"

        print("\n==================================================")
        print("   🎉 REBUILD & PACKAGING COMPLETE!               ")
        print("==================================================")
        print(f"📌 Standalone Executable (.exe):")
        print(f"   👉 {exe_file}")
        print(f"\n📌 MSIX Package Source Folder (for MSIX Hero):")
        print(f"   👉 {staging_dir}")
        print("==================================================")
    else:
        print("[!] Compilation failed.")

if __name__ == "__main__":
    rebuild_all()
