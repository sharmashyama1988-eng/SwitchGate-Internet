"""
SwitchGate - Turbo Fast Packager & Deployment Optimizer
Compresses directly to local SSD using zlib level 1 (fastest), then streams single sequential file to USB.
"""
import os
import sys
import time
import shutil
import zipfile
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist" / "SwitchGate"
TEMP_DIR = Path(tempfile.gettempdir())
TEMP_ZIP = TEMP_DIR / "SwitchGate-v2.0-Standalone-Win64.zip"
FINAL_ZIP = BASE_DIR / "dist" / "SwitchGate-v2.0-Standalone-Win64.zip"

def main():
    print("==================================================")
    print("   ⚡ SWITCHGATE TURBO PACKAGER (SSD ACCELERATED)  ")
    print("==================================================")
    t0 = time.perf_counter()

    # 1. Fast sync latest backend/firewall/frontend into dist/SwitchGate
    print("[1/3] Syncing latest code into dist/SwitchGate...")
    def sync_dirs(src, dst):
        s_dir, d_dir = Path(src), Path(dst)
        d_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for root, dirs, files in os.walk(s_dir):
            if any(x in root for x in ['__pycache__', '.git', '.pytest_cache']):
                continue
            rel = Path(root).relative_to(s_dir)
            t_sub = d_dir / rel
            t_sub.mkdir(parents=True, exist_ok=True)
            for f in files:
                sf = Path(root) / f
                df = t_sub / f
                if not df.exists() or sf.stat().st_mtime > df.stat().st_mtime or sf.stat().st_size != df.stat().st_size:
                    shutil.copy2(sf, df)
                    count += 1
        return count

    c1 = sync_dirs(BASE_DIR / "backend", DIST_DIR / "_internal" / "backend")
    c2 = sync_dirs(BASE_DIR / "firewall", DIST_DIR / "_internal" / "firewall")
    c3 = sync_dirs(BASE_DIR / "frontend", DIST_DIR / "frontend")
    print(f"      [✓] Code sync complete ({c1 + c2 + c3} files updated).")

    # 2. Compress directly on NVMe SSD
    print(f"[2/3] Compressing package on NVMe SSD: {TEMP_ZIP.name}...")
    t_zip = time.perf_counter()
    if TEMP_ZIP.exists():
        try:
            TEMP_ZIP.unlink()
        except Exception:
            pass

    with zipfile.ZipFile(str(TEMP_ZIP), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        for root, dirs, files in os.walk(DIST_DIR):
            for file in files:
                full_path = Path(root) / file
                arcname = full_path.relative_to(DIST_DIR.parent)
                zf.write(full_path, arcname)

    zip_sec = round(time.perf_counter() - t_zip, 1)
    zip_size_mb = round(TEMP_ZIP.stat().st_size / (1024 * 1024), 1)
    print(f"      [✓] SSD Compression finished in {zip_sec}s ({zip_size_mb} MB).")

    # 3. Stream single sequential file to USB / target drive
    print(f"[3/3] Streaming single archive to USB drive: {FINAL_ZIP}...")
    t_copy = time.perf_counter()
    shutil.copy2(str(TEMP_ZIP), str(FINAL_ZIP))
    copy_sec = round(time.perf_counter() - t_copy, 1)
    print(f"      [✓] Transferred to USB in {copy_sec}s.")

    # Clean SSD temp
    try:
        TEMP_ZIP.unlink()
    except Exception:
        pass

    total_sec = round(time.perf_counter() - t0, 1)
    exe_file = DIST_DIR / "SwitchGate.exe"
    exe_size_mb = round(exe_file.stat().st_size / (1024 * 1024), 1) if exe_file.exists() else 0.0

    print("\n==================================================")
    print("   🎉 FAST BUILD & PACKAGING COMPLETED IN RECORD TIME!")
    print(f"   ⏱️ Total Elapsed Time: {total_sec} seconds")
    print(f"   📍 Standalone Executable: {exe_file} ({exe_size_mb} MB)")
    print(f"   📦 Portable ZIP Package: {FINAL_ZIP} ({zip_size_mb} MB)")
    print("==================================================")

if __name__ == "__main__":
    main()
