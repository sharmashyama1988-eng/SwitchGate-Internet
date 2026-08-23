"""
SwitchGate - MSIX Source Folder Updater
Stages the latest compiled build into a clean MSIX_Source folder
ready for MSIX Hero / MakeAppx packaging.
"""
import os
import sys
import shutil
import glob
import subprocess
from pathlib import Path

BASE_DIR  = Path(__file__).resolve().parent
DIST_DIR  = BASE_DIR / "dist" / "SwitchGate"
MSIX_DIR  = BASE_DIR / "MSIX_Source"
ASSETS    = BASE_DIR / "assets"
MANIFEST  = BASE_DIR / "msix" / "AppxManifest.xml"
OUTPUT    = BASE_DIR / "SwitchGate Internet.msix"

def build_msix_source():
    print("=" * 52)
    print("   📦 UPDATING MSIX SOURCE FOLDER")
    print("=" * 52)

    # ── 1. Verify compiled exe exists ─────────────────────
    if not (DIST_DIR / "SwitchGate.exe").exists():
        print("[!] SwitchGate.exe not found in dist/. Run build_exe.py first.")
        return False

    # ── 2. Clean previous MSIX_Source ────────────────────
    if MSIX_DIR.exists():
        shutil.rmtree(MSIX_DIR)
    MSIX_DIR.mkdir()
    print(f"[1/5] Clean MSIX_Source folder created.")

    # ── 3. Copy compiled app ──────────────────────────────
    shutil.copytree(DIST_DIR, MSIX_DIR, dirs_exist_ok=True)
    print(f"[2/5] Compiled app staged ({DIST_DIR.name} → MSIX_Source/).")

    # ── 4. Stage Assets (Store logo images) ──────────────
    dest_assets = MSIX_DIR / "Assets"
    dest_assets.mkdir(exist_ok=True)
    count = 0
    for f in ASSETS.glob("*.png"):
        shutil.copy2(f, dest_assets / f.name)
        count += 1
    print(f"[3/5] {count} store assets staged in Assets/.")

    # ── 5. Stage AppxManifest.xml ─────────────────────────
    shutil.copy2(MANIFEST, MSIX_DIR / "AppxManifest.xml")
    print(f"[4/5] AppxManifest.xml (v2.0.2.0) staged.")

    # ── 6. Summary ────────────────────────────────────────
    total_files = sum(1 for _ in MSIX_DIR.rglob("*") if _.is_file())
    total_mb    = round(sum(f.stat().st_size for f in MSIX_DIR.rglob("*") if f.is_file()) / (1024*1024), 1)
    print(f"[5/5] MSIX_Source ready: {total_files} files, {total_mb} MB")

    # ── 7. Try MakeAppx if available ─────────────────────
    makeappx = _find_makeappx()
    if makeappx:
        print(f"\n[✓] MakeAppx found: {makeappx}")
        print("[*] Auto-packaging MSIX...")
        r = subprocess.run(
            [makeappx, "pack", "/d", str(MSIX_DIR), "/p", str(OUTPUT), "/nv", "/o"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            sz = round(OUTPUT.stat().st_size / (1024*1024), 1)
            print(f"\n{'='*52}")
            print(f"   ✅ MSIX AUTO-BUILT: {OUTPUT.name} ({sz} MB)")
            print(f"   📍 {OUTPUT}")
            print(f"{'='*52}")
            return True
        else:
            print(f"[!] MakeAppx error: {r.stderr[:200]}")

    # ── 8. MSIX Hero instructions ─────────────────────────
    print(f"\n{'='*52}")
    print(f"   ✅ MSIX SOURCE READY FOR MSIX HERO")
    print(f"{'='*52}")
    print(f"\n📁 Source Folder: {MSIX_DIR}")
    print(f"\nMSIX Hero Steps:")
    print(f"  1. Open MSIX Hero")
    print(f"  2. Click 'Pack' → 'Pack directory'")
    print(f"  3. Select: {MSIX_DIR}")
    print(f"  4. Output:  {OUTPUT}")
    print(f"  5. Click Pack → Done ✅")
    print(f"\nThen upload to Microsoft Store Partner Center.")
    return True

def _find_makeappx():
    patterns = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe",
        r"C:\Program Files\Windows Kits\10\bin\*\x64\makeappx.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\*\arm64\makeappx.exe",
    ]
    for pat in patterns:
        hits = sorted(glob.glob(pat), reverse=True)
        if hits:
            return hits[0]
    return None

if __name__ == "__main__":
    build_msix_source()
