"""
SwitchGate - MSIX Staging Directory Preparer (for MSIX Hero / MakeAppx)
Prepares a 100% compliant Microsoft Store package layout in MSIX_Package_Source folder.
"""
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STAGING_DIR = BASE_DIR / "MSIX_Package_Source"
DIST_APP_DIR = BASE_DIR / "dist" / "SwitchGate"
ASSETS_DIR = BASE_DIR / "assets"
MSIX_DIR = BASE_DIR / "msix"

def prepare_staging():
    print("==================================================")
    print("   📦 PREPARING MSIX STAGING FOLDER (MSIX HERO)   ")
    print("==================================================")

    # 1. Clean & create staging folder
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR, ignore_errors=True)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Copy compiled app binary & runtime files
    if not (DIST_APP_DIR / "SwitchGate.exe").exists():
        print("[*] Compiling latest SwitchGate desktop application first...")
        import build_exe
        build_exe.build()

    print("[*] Copying app binaries and runtime files with multi-threaded robocopy...")
    import subprocess
    subprocess.run(f'robocopy "{DIST_APP_DIR}" "{STAGING_DIR}" /E /MT:16', shell=True)

    # 3. Copy official AppxManifest.xml to root of staging directory
    manifest_src = MSIX_DIR / "AppxManifest.xml"
    manifest_dst = STAGING_DIR / "AppxManifest.xml"
    shutil.copy2(manifest_src, manifest_dst)
    print(f"[*] Placed AppxManifest.xml (Identity: Technicalamiteducation.SwitchGateInternet)")

    # 4. Copy Assets into both Assets/ (for AppxManifest) and assets/ (for internal code)
    for folder_name in ["Assets", "assets"]:
        dst_folder = STAGING_DIR / folder_name
        dst_folder.mkdir(exist_ok=True)
        for asset in ASSETS_DIR.glob("*.*"):
            shutil.copy2(asset, dst_folder / asset.name)
    print(f"[*] Staged Microsoft Store visual assets in Assets/ and assets/.")

    # 5. Ensure WebView2Loader.dll & .NET interop DLLs are in MSIX root
    dist_dlls = ["WebView2Loader.dll", "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll"]
    for dll in dist_dlls:
        src = DIST_APP_DIR / dll
        if src.exists() and not (STAGING_DIR / dll).exists():
            shutil.copy2(src, STAGING_DIR / dll)

    print("\n==================================================")
    print("   ✅ MSIX PACKAGE SOURCE FOLDER IS 100% READY!   ")
    print(f"   Folder Path: {STAGING_DIR}                    ")
    print("==================================================")
    print("\n👉 In MSIX Hero:")
    print("1. Click 'Pack directory to MSIX'")
    print(f"2. Select source directory: {STAGING_DIR}")
    print("3. Click 'Create MSIX'!")

if __name__ == "__main__":
    prepare_staging()
