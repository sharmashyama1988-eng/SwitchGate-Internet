"""
SwitchGate - Standalone Native Desktop App (.EXE) Builder
Compiles PyWebView (EdgeChromium), PyStray Tray, FastAPI, and Native Engines into a standalone Windows .exe.
Explicitly bundles C-extension DLLs, .NET assemblies, and WebView2 loaders.
"""
import os
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SSD_BUILD_ROOT = Path(os.environ.get("TEMP", tempfile.gettempdir())) / "SwitchGate_SSD_Build"

def find_file_in_tree(root: Path, filename: str) -> Path | None:
    for p in root.rglob(filename):
        if p.is_file():
            return p
    return None

def build():
    print("==================================================")
    print("   ⚡ BUILDING SWITCHGATE STANDALONE APP (.EXE)   ")
    print("==================================================")

    f_dist_dir = BASE_DIR / "dist"
    f_build_dir = BASE_DIR / "build"

    ssd_dist_dir = SSD_BUILD_ROOT / "dist"
    ssd_work_dir = SSD_BUILD_ROOT / "build"

    # Clean previous artifacts on both drives
    if f_dist_dir.exists():
        shutil.rmtree(f_dist_dir, ignore_errors=True)
    if f_build_dir.exists():
        shutil.rmtree(f_build_dir, ignore_errors=True)
    if SSD_BUILD_ROOT.exists():
        shutil.rmtree(SSD_BUILD_ROOT, ignore_errors=True)

    SSD_BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    f_dist_dir.mkdir(parents=True, exist_ok=True)

    frontend_dir = BASE_DIR / "frontend"
    crashpad_dir = BASE_DIR / "crashpad"
    assets_dir = BASE_DIR / "assets"
    icon_path = assets_dir / "icon.ico"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--noupx",
        "--name=SwitchGate",
        "--uac-admin",
        f"--distpath={ssd_dist_dir}",
        f"--workpath={ssd_work_dir}",
        f"--specpath={SSD_BUILD_ROOT}",
        f"--icon={icon_path}",
        f"--add-data={frontend_dir}{os.pathsep}frontend",
        f"--add-data={crashpad_dir}{os.pathsep}crashpad",
        f"--add-data={assets_dir}{os.pathsep}assets",
        f"--add-data={BASE_DIR / 'firewall'}{os.pathsep}firewall",
    ]

    # Explicitly bundle C-extension PYDs from Python DLLs directory
    py_dlls_dir = Path(sys.executable).parent / "DLLs"
    if py_dlls_dir.exists():
        for pyd_file in py_dlls_dir.glob("*.pyd"):
            cmd.append(f"--add-binary={pyd_file}{os.pathsep}.")

    cmd.extend([
        # ── Exclude modules NOT used by SwitchGate ─────────────────────────
        # tkinter: app uses WebView2 (EdgeChromium), NOT tkinter GUI
        # Excluding it removes pyi_rth__tkinter hook which crashes in MSIX
        "--exclude-module=tkinter",
        "--exclude-module=_tkinter",
        "--exclude-module=Tkinter",
        "--exclude-module=tkinter.ttk",
        "--exclude-module=tkinter.messagebox",
        "--exclude-module=tkinter.filedialog",
        "--exclude-module=turtle",
        "--exclude-module=turtledemo",
        "--exclude-module=test",
        "--exclude-module=unittest",
        "--exclude-module=email.mime",
        "--exclude-module=xmlrpc",
        "--exclude-module=ftplib",
        "--exclude-module=imaplib",
        "--exclude-module=poplib",
        "--exclude-module=telnetlib",
        "--exclude-module=nntplib",

        # ── Package collections ────────────────────────────────────────────
        "--collect-all=webview",
        "--collect-all=bottle",
        "--collect-all=pythonnet",
        "--collect-all=clr_loader",
        "--collect-all=pystray",
        "--collect-all=PIL",
        "--collect-all=scapy",
        "--collect-all=fastapi",
        "--collect-all=starlette",
        "--collect-all=uvicorn",
        "--collect-all=pydantic",
        "--collect-all=pydantic_core",
        "--collect-all=aiosqlite",
        "--collect-all=dnslib",
        "--collect-all=websockets",
        "--collect-all=crashpad",

        # Standard library & core hidden imports
        "--hidden-import=unicodedata",
        "--hidden-import=clr",
        "--hidden-import=ctypes",
        "--hidden-import=ctypes.wintypes",
        "--hidden-import=sqlite3",
        "--hidden-import=psutil",
        "--hidden-import=socket",
        "--hidden-import=asyncio",
        "--hidden-import=threading",
        "--hidden-import=urllib.request",
        "--hidden-import=urllib.parse",
        "--hidden-import=json",
        "--hidden-import=wsgiref",
        "--hidden-import=wsgiref.simple_server",
        "--hidden-import=pystray",
        "--hidden-import=PIL",
        "--hidden-import=PIL.Image",
        "--hidden-import=PIL.ImageDraw",

        # All Backend modules
        "--hidden-import=backend",
        "--hidden-import=backend.main",
        "--hidden-import=backend.config",
        "--hidden-import=backend.database",
        "--hidden-import=backend.core",
        "--hidden-import=backend.core.activator",
        "--hidden-import=backend.core.admin_power",
        "--hidden-import=backend.core.scanner",
        "--hidden-import=backend.core.blocker",
        "--hidden-import=backend.core.dns_sinkhole",
        "--hidden-import=backend.core.traffic_monitor",
        "--hidden-import=backend.core.scheduler",
        "--hidden-import=backend.core.ghost_detector",
        "--hidden-import=backend.core.intruder_detector",
        "--hidden-import=backend.core.system_integration",
        "--hidden-import=backend.core.app_controller",
        "--hidden-import=backend.core.url_controller",
        "--hidden-import=backend.core.blackhole_proxy",
        "--hidden-import=backend.core.oui_database",
        "--hidden-import=backend.adblock",
        "--hidden-import=backend.adblock.adblock_engine",
        "--hidden-import=backend.adblock.rules",
        "--hidden-import=backend.kperf",
        "--hidden-import=backend.kperf.kperf_engine",
        "--hidden-import=backend.kperf.kperf_bridge",
        "--hidden-import=backend.native",
        "--hidden-import=backend.native.network_engine",
        "--hidden-import=backend.native.startup_manager",
        "--hidden-import=backend.routers",
        "--hidden-import=backend.routers.devices",
        "--hidden-import=backend.routers.network",
        "--hidden-import=backend.routers.adblock",
        "--hidden-import=backend.routers.schedules",
        "--hidden-import=backend.routers.intruders",
        "--hidden-import=backend.routers.ghost_leaks",
        "--hidden-import=backend.routers.settings",
        "--hidden-import=backend.routers.apps",
        "--hidden-import=backend.routers.websites",
        "--hidden-import=backend.routers.kperf",

        # Firewall modules
        "--hidden-import=firewall",
        "--hidden-import=firewall.rules_engine",
        "--hidden-import=firewall.antivirus",
        "--hidden-import=firewall.packet_filter",
        "--hidden-import=firewall.firewall_logger",
        "--hidden-import=firewall.firewall_controller",
        "--hidden-import=firewall.firewall_router",

        # Uvicorn internals
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.websockets",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespans",
        "--hidden-import=uvicorn.lifespans.on",

        str(BASE_DIR / "desktop_app.py")
    ])

    print("[*] Executing PyInstaller build...")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        compiled_ssd_app = ssd_dist_dir / "SwitchGate"
        target_f_app = f_dist_dir / "SwitchGate"

        print(f"[*] Moving compiled binary to workspace: {target_f_app}...")
        subprocess.run(f'robocopy "{compiled_ssd_app}" "{target_f_app}" /E /MT:16', shell=True)

        internal_dir = target_f_app / "_internal"
        internal_webview_lib = internal_dir / "webview" / "lib"

        # 1. Locate and Stage WebView2Loader.dll
        loader_src = internal_webview_lib / "runtimes" / "win-x64" / "native" / "WebView2Loader.dll"
        if not loader_src.exists():
            loader_src = find_file_in_tree(internal_dir, "WebView2Loader.dll")

        if loader_src and loader_src.exists():
            # Stage in app root
            shutil.copy2(loader_src, target_f_app / "WebView2Loader.dll")
            # Stage in _internal root
            shutil.copy2(loader_src, internal_dir / "WebView2Loader.dll")
            # Stage in runtimes/win-x64/native
            native_dest = target_f_app / "runtimes" / "win-x64" / "native"
            native_dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(loader_src, native_dest / "WebView2Loader.dll")
            # Stage in x64/
            x64_dest = target_f_app / "x64"
            x64_dest.mkdir(exist_ok=True)
            shutil.copy2(loader_src, x64_dest / "WebView2Loader.dll")
            # Stage in win-x64/
            win_x64_dest = target_f_app / "win-x64"
            win_x64_dest.mkdir(exist_ok=True)
            shutil.copy2(loader_src, win_x64_dest / "WebView2Loader.dll")
            print("[+] Staged WebView2Loader.dll in root, _internal, runtimes/, x64/, and win-x64/.")

        # 2. Locate and Stage .NET & WebView2 Interop DLLs
        interop_dlls = [
            "Microsoft.Web.WebView2.Core.dll",
            "Microsoft.Web.WebView2.WinForms.dll",
            "WebBrowserInterop.x64.dll",
            "WebBrowserInterop.x86.dll"
        ]
        for dll_name in interop_dlls:
            dll_src = internal_webview_lib / dll_name
            if not dll_src.exists():
                dll_src = find_file_in_tree(internal_dir, dll_name)
            if dll_src and dll_src.exists():
                shutil.copy2(dll_src, target_f_app / dll_name)
                shutil.copy2(dll_src, internal_dir / dll_name)
                print(f"[+] Staged {dll_name} in app root and _internal.")

        # 3. Locate and Stage PythonNet / CLR Loader DLLs
        clr_dlls = ["Python.Runtime.dll", "ClrLoader.dll"]
        for dll_name in clr_dlls:
            dll_src = find_file_in_tree(internal_dir, dll_name)
            if dll_src and dll_src.exists():
                shutil.copy2(dll_src, target_f_app / dll_name)
                shutil.copy2(dll_src, internal_dir / dll_name)
                print(f"[+] Staged CLR {dll_name} in app root and _internal.")

        # 4. Stage Assets Directory
        target_assets = target_f_app / "assets"
        target_assets.mkdir(exist_ok=True)
        if assets_dir.exists():
            for asset_f in assets_dir.glob("*.*"):
                shutil.copy2(asset_f, target_assets / asset_f.name)
            print(f"[+] Staged assets in {target_assets}.")

        # 5. Stage Frontend Directory
        target_frontend = target_f_app / "frontend"
        if not target_frontend.exists() and frontend_dir.exists():
            shutil.copytree(frontend_dir, target_frontend)
            print(f"[+] Staged frontend in {target_frontend}.")

        # Clean SSD temporary build directory
        print("[*] Cleaning up SSD temporary build files...")
        shutil.rmtree(SSD_BUILD_ROOT, ignore_errors=True)

        exe_path = target_f_app / "SwitchGate.exe"
        print("\n==================================================")
        print("   ✅ STANDALONE NATIVE APP COMPILED SUCCESSFULLY!")
        print(f"   Executable Location: {exe_path}               ")
        print("==================================================")
        return True
    else:
        shutil.rmtree(SSD_BUILD_ROOT, ignore_errors=True)
        print("\n[!] Build failed. Check compiler output above.")
        return False

if __name__ == "__main__":
    build()
