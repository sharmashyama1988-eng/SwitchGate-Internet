import sys
import time
import shutil
import subprocess
from pathlib import Path

t0 = time.time()
base = Path(".").resolve()
dist_app = base / "dist" / "SwitchGate"
manifest = base / "msix" / "AppxManifest.xml"
assets = base / "assets"
makeappx = base / "tools" / "bin" / "makeappx.exe"

print("[1/4] Copying Manifest and Assets into dist/SwitchGate...")
shutil.copy2(manifest, dist_app / "AppxManifest.xml")
(dist_app / "Assets").mkdir(exist_ok=True)
for p in assets.glob("*.png"):
    shutil.copy2(p, dist_app / "Assets" / p.name)
print("    Done in {:.2f}s".format(time.time() - t0))

print("[2/4] Packing MSIX to SSD TEMP using makeappx...")
t_pack = time.time()
temp_msix = Path("C:/Windows/Temp/SwitchGate_v2.0.4.0.msix")
if not temp_msix.parent.exists():
    import tempfile
    temp_msix = Path(tempfile.gettempdir()) / "SwitchGate_v2.0.4.0.msix"

cmd = [str(makeappx), "pack", "/d", str(dist_app), "/p", str(temp_msix), "/nv", "/o"]
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("MakeAppx ERROR:")
    print(res.stdout)
    print(res.stderr)
    sys.exit(1)
print("    Packed in {:.2f}s".format(time.time() - t_pack))

print("[3/4] Copying MSIX to workspace...")
out_root = base / "SwitchGate Internet.msix"
out_dist = base / "dist" / "SwitchGateInternet_2.0.4.0_x64.msix"
shutil.copy2(temp_msix, out_root)
shutil.copy2(temp_msix, out_dist)

# Also update MSIX_Source manifest and assets so MSIX_Source is 100% updated too
msix_source = base / "MSIX_Source"
if msix_source.exists():
    shutil.copy2(manifest, msix_source / "AppxManifest.xml")
    (msix_source / "Assets").mkdir(exist_ok=True)
    for p in assets.glob("*.png"):
        shutil.copy2(p, msix_source / "Assets" / p.name)

print("[4/4] Verifying MSIX...")
import zipfile
with zipfile.ZipFile(out_root, "r") as zf:
    names = set(zf.namelist())
    for f in ["AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml", "SwitchGate.exe"]:
        assert any(n.replace("\\", "/") == f for n in names), f"Missing {f}"

sz = round(out_root.stat().st_size / (1024 * 1024), 2)
total = time.time() - t0
print("=" * 50)
print(f"✅ MSIX BUILT IN {total:.1f} SECONDS!")
print(f"File: {out_root}")
print(f"Size: {sz} MB")
print("=" * 50)
