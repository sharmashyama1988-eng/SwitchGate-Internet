"""
SwitchGate - Windows SDK MakeAppx Downloader & Packager
Downloads official Microsoft Windows SDK BuildTools from NuGet to ensure 100% valid Microsoft Store MSIX packaging.
"""
import os
import sys
import io
import zipfile
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR / "tools" / "bin"
TOOLS_DIR.mkdir(parents=True, exist_ok=True)

NUGET_URL = "https://www.nuget.org/api/v2/package/Microsoft.Windows.SDK.BuildTools/10.0.22621.756"

def ensure_makeappx() -> Path:
    makeappx_exe = TOOLS_DIR / "makeappx.exe"
    if makeappx_exe.exists():
        return makeappx_exe

    print("[*] Downloading official Microsoft Windows SDK BuildTools from NuGet (for MakeAppx)...")
    req = urllib.request.Request(NUGET_URL, headers={"User-Agent": "SwitchGate-Builder"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    print(f"[*] Downloaded {len(data) / (1024*1024):.2f} MB. Extracting x64 packaging binaries & manifests...")
    prefix = "bin/10.0.22621.0/x64/"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():
            if member.startswith(prefix) and not member.endswith("/"):
                rel_path = member[len(prefix):]
                target = TOOLS_DIR / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                if target.name in ["makeappx.exe", "makepri.exe", "signtool.exe", "appxpackaging.dll"]:
                    print(f"   + Extracted: {rel_path}")

    print(f"[✅] Official Microsoft MakeAppx ready at: {makeappx_exe}")
    return makeappx_exe

if __name__ == "__main__":
    ensure_makeappx()
