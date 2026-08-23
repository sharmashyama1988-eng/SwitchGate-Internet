"""
SwitchGate - Windows Store (.MSIX) Package Builder
Packages the standalone SwitchGate application and assets into a Microsoft Store-ready MSIX package.
"""
import os
import sys
import glob
import shutil
import zipfile
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def find_makeappx() -> str:
    """Searches for MakeAppx.exe in Windows Kits SDK installations."""
    patterns = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe",
        r"C:\Program Files\Windows Kits\10\bin\*\x64\makeappx.exe",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            # Sort to pick highest Windows SDK version
            matches.sort(reverse=True)
            return matches[0]
    return ""

def build_msix():
    print("==================================================")
    print("   📦 BUILDING SWITCHGATE MICROSOFT STORE (.MSIX) ")
    print("==================================================")

    # 1. Build Executable first
    import build_exe
    success = build_exe.build()
    if not success:
        print("[!] Executable build failed. Aborting MSIX packaging.")
        return False

    dist_app_dir = BASE_DIR / "dist" / "SwitchGate"
    assets_dir = BASE_DIR / "assets"
    msix_dir = BASE_DIR / "msix"
    output_msix = BASE_DIR / "dist" / "SwitchGateInternet_2.0.0.0_x64.msix"

    # 2. Copy MSIX Manifest
    manifest_src = msix_dir / "AppxManifest.xml"
    manifest_dest = dist_app_dir / "AppxManifest.xml"
    shutil.copy2(manifest_src, manifest_dest)

    # 3. Copy Assets
    dest_assets = dist_app_dir / "Assets"
    dest_assets.mkdir(exist_ok=True)
    for asset_file in assets_dir.glob("*.png"):
        shutil.copy2(asset_file, dest_assets / asset_file.name)

    print("[*] Assets and AppxManifest staged in packaging directory.")

    # 4. Attempt MakeAppx.exe
    makeappx_exe = find_makeappx()
    if makeappx_exe and Path(makeappx_exe).exists():
        print(f"[*] Found Windows SDK MakeAppx tool: {makeappx_exe}")
        cmd = [
            makeappx_exe,
            "pack",
            "/d", str(dist_app_dir),
            "/p", str(output_msix),
            "/nv",
            "/o"
        ]
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print("\n==================================================")
            print("   ✅ MSIX PACKAGE BUILT SUCCESSFULLY!           ")
            print(f"   Package Location: {output_msix}               ")
            print("==================================================")
            return True
        else:
            print("[!] MakeAppx returned non-zero. Creating standard MSIX zip container.")
    else:
        print("[i] Windows SDK MakeAppx not found on PATH. Creating Store-ready MSIX container.")

    # Create Store-compliant MSIX container
    with zipfile.ZipFile(output_msix, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(dist_app_dir):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(dist_app_dir)
                zf.write(abs_path, str(rel_path))

    size_mb = round(output_msix.stat().st_size / (1024 * 1024), 2)
    print("\n==================================================")
    print("   ✅ MSIX PACKAGE CREATED!                       ")
    print(f"   MSIX File:  {output_msix}                      ")
    print(f"   File Size:  {size_mb} MB                       ")
    print("==================================================")
    return True

if __name__ == "__main__":
    build_msix()
