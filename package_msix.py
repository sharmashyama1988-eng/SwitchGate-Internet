"""
SwitchGate - High-Speed MSIX Packager for Microsoft Partner Center
Packages SwitchGate into a 100% compliant Microsoft Store .msix package using makeappx.exe.
Optimized for NVMe SSD staging to bypass USB exFAT latency.
"""
import os
import sys
import shutil
import time
import zipfile
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DIST_APP_DIR = BASE_DIR / "dist" / "SwitchGate"
ASSETS_DIR = BASE_DIR / "assets"
MANIFEST_FILE = BASE_DIR / "msix" / "AppxManifest.xml"
MAKEAPPX_EXE = BASE_DIR / "tools" / "bin" / "makeappx.exe"

OUTPUT_ROOT_MSIX = BASE_DIR / "SwitchGate Internet.msix"
OUTPUT_DIST_MSIX = BASE_DIR / "dist" / "SwitchGateInternet_2.0.4.0_x64.msix"

def package_msix():
    start_time = time.time()
    print("=" * 60)
    print("   PACKAGING SWITCHGATE MICROSOFT STORE (.MSIX)")
    print("=" * 60)

    if not (DIST_APP_DIR / "SwitchGate.exe").exists():
        print("[!] ERROR: dist/SwitchGate/SwitchGate.exe not found!")
        return False

    if not MANIFEST_FILE.exists():
        print(f"[!] ERROR: Manifest not found at {MANIFEST_FILE}")
        return False

    if not MAKEAPPX_EXE.exists():
        print(f"[!] ERROR: makeappx.exe not found at {MAKEAPPX_EXE}")
        return False

    temp_dir = Path(os.environ.get("TEMP", "C:/Windows/Temp"))
    staging_dir = temp_dir / "SwitchGate_MSIX_Staging"
    temp_msix = temp_dir / "SwitchGateInternet_2.0.4.0_x64.msix"

    if staging_dir.exists():
        print("[*] Cleaning previous staging directory...")
        shutil.rmtree(staging_dir, ignore_errors=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    if temp_msix.exists():
        temp_msix.unlink()

    print(f"[*] Staging application files to NVMe SSD ({staging_dir})...")
    stage_t0 = time.time()
    robocopy_cmd = [
        "robocopy", str(DIST_APP_DIR), str(staging_dir),
        "/MIR", "/R:1", "/W:1", "/NFL", "/NDL", "/NP", "/NJH", "/NJS"
    ]
    subprocess.run(robocopy_cmd, shell=True)
    print(f"[+] App files staged in {time.time() - stage_t0:.1f}s")

    print("[*] Staging Store Assets and AppxManifest.xml...")
    staging_assets = staging_dir / "Assets"
    staging_assets.mkdir(exist_ok=True)
    for png in ASSETS_DIR.glob("*.png"):
        shutil.copy2(png, staging_assets / png.name)

    shutil.copy2(MANIFEST_FILE, staging_dir / "AppxManifest.xml")
    print("[+] Store Assets and AppxManifest.xml staged.")

    print("[*] Executing makeappx.exe pack on SSD...")
    pack_t0 = time.time()
    cmd = [
        str(MAKEAPPX_EXE),
        "pack",
        "/d", str(staging_dir),
        "/p", str(temp_msix),
        "/nv",
        "/o"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] makeappx failed with code {res.returncode}:")
        print(res.stdout)
        print(res.stderr)
        return False
    print(f"[+] makeappx pack completed in {time.time() - pack_t0:.1f}s")

    print("[*] Verifying generated MSIX package structure...")
    with zipfile.ZipFile(temp_msix, "r") as zf:
        namelist = set(zf.namelist())
        required_files = [
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "SwitchGate.exe",
            "Assets/StoreLogo.png",
            "Assets/Square150x150Logo.png",
            "Assets/Square44x44Logo.png"
        ]
        for req in required_files:
            matched = any(f.replace("\\", "/") == req for f in namelist)
            if not matched:
                print(f"[!] Warning: Required MSIX entry '{req}' missing from package!")
            else:
                print(f"    [+] {req} verified")

    print(f"[*] Copying MSIX to target destinations...")
    OUTPUT_DIST_MSIX.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(temp_msix, OUTPUT_ROOT_MSIX)
    shutil.copy2(temp_msix, OUTPUT_DIST_MSIX)

    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
        temp_msix.unlink(missing_ok=True)
    except Exception:
        pass

    size_mb = round(OUTPUT_ROOT_MSIX.stat().st_size / (1024 * 1024), 2)
    total_duration = time.time() - start_time
    print("=" * 60)
    print("   MSIX PACKAGE READY FOR MICROSOFT PARTNER CENTER!")
    print("=" * 60)
    print(f"   Root File:     {OUTPUT_ROOT_MSIX}")
    print(f"   Dist File:     {OUTPUT_DIST_MSIX}")
    print(f"   Package Size:  {size_mb} MB")
    print(f"   Build Time:    {total_duration:.1f} seconds")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = package_msix()
    sys.exit(0 if success else 1)
