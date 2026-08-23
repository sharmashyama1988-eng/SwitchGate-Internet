"""
SwitchGate - Standalone Native Desktop App (Zero-Browser Dependency)
Embeds Microsoft Edge Chromium WebView2 engine into a dedicated native Windows GUI window
with System Tray integration, Silent Admin Elevation, and background FastAPI Core.
MSIX / Microsoft Store safe: never accesses read-only WindowsApps directory.
"""
import os
import sys
import time
import tempfile
import threading
import urllib.request
from pathlib import Path

# Force pystray to use pure Win32 backend (NOT tkinter backend)
os.environ["PYSTRAY_BACKEND"] = "win32"

# ─────────────────────────────────────────────────────────────────────────────
# 0. MSIX-safe writable base paths BEFORE any other import
#    (config.py will also resolve this, but we need it early for cache dir)
# ─────────────────────────────────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = Path(sys._MEIPASS)
    BASE_DIR   = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    BASE_DIR   = BUNDLE_DIR

_READONLY_MARKERS = ("windowsapps", "program files", "program files (x86)")

def _safe_local_app_data() -> Path:
    """Returns a guaranteed-writable AppData path, bypassing MSIX env virtualization."""
    # Try registry first (most reliable in MSIX context)
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        ) as key:
            v, _ = winreg.QueryValueEx(key, "Local AppData")
            p = Path(v)
            if p.exists() and not any(m in str(p).lower() for m in _READONLY_MARKERS):
                return p
    except Exception:
        pass
    # Env var fallback
    for env in ("LOCALAPPDATA", "APPDATA"):
        v = os.environ.get(env, "")
        if v and not any(m in v.lower() for m in _READONLY_MARKERS):
            return Path(v)
    # Home fallback
    try:
        h = Path.home()
        if not any(m in str(h).lower() for m in _READONLY_MARKERS):
            return h / "AppData" / "Local"
    except Exception:
        pass
    return Path(tempfile.gettempdir())

_USER_LOCAL = _safe_local_app_data()

# ─────────────────────────────────────────────────────────────────────────────
# 1. Native Windows DLL & WebView2 Assembly Search Path Config
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform == "win32":
    search_paths = [
        str(BASE_DIR),
        str(BUNDLE_DIR),
        str(BUNDLE_DIR / "webview" / "lib"),
        str(BUNDLE_DIR / "webview" / "lib" / "runtimes" / "win-x64" / "native"),
        str(BASE_DIR / "runtimes" / "win-x64" / "native"),
        str(BASE_DIR / "x64"),
        str(BASE_DIR / "win-x64"),
        str(BUNDLE_DIR / "clr_loader" / "ffi" / "dlls" / "amd64"),
        str(BUNDLE_DIR / "pythonnet" / "runtime"),
        str(BASE_DIR / "clr_loader" / "ffi" / "dlls" / "amd64"),
        str(BASE_DIR / "pythonnet" / "runtime"),
    ]
    for p in search_paths:
        if os.path.exists(p):
            try:
                os.add_dll_directory(p)
            except Exception:
                pass

    try:
        import ctypes
        ctypes.windll.kernel32.SetDllDirectoryW(str(BASE_DIR))
    except Exception:
        pass

    # Ensure PATH has these directories for unmanaged DLL loaders
    valid_paths = [p for p in search_paths if os.path.exists(p)]
    if valid_paths:
        os.environ["PATH"] = ";".join(valid_paths) + ";" + os.environ.get("PATH", "")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Suppress Scapy / libpcap warnings BEFORE any backend import
# ─────────────────────────────────────────────────────────────────────────────
import logging as _log_setup
_log_setup.getLogger("scapy.runtime").setLevel(_log_setup.ERROR)
_log_setup.getLogger("scapy").setLevel(_log_setup.ERROR)
import warnings as _warn_setup
_warn_setup.filterwarnings("ignore", message=".*libpcap.*")
_warn_setup.filterwarnings("ignore", message=".*pcap.*")
_warn_setup.filterwarnings("ignore", category=RuntimeWarning, module="scapy")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Configure Dedicated WebView2 User Cache Directory (MSIX-safe writable path)
# ─────────────────────────────────────────────────────────────────────────────
WEBVIEW2_CACHE = _USER_LOCAL / "SwitchGate" / "WebView2Cache"
try:
    WEBVIEW2_CACHE.mkdir(parents=True, exist_ok=True)
    os.environ["WEBVIEW2_USER_DATA_FOLDER"] = str(WEBVIEW2_CACHE)
except Exception:
    pass

import uvicorn
import webview

from backend.config import AppConfig
from backend.database import db

def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def elevate_if_needed():
    """Requests Administrator elevation once on Windows launch."""
    if getattr(sys, 'frozen', False):
        return  # Frozen executable manifest enforces uac_admin=True
    if os.name == "nt" and not is_admin():
        if "--no-elevate" not in sys.argv:
            try:
                import ctypes
                params = " ".join([f'"{arg}"' for arg in sys.argv] + ["--no-elevate"])
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                if ret > 32:
                    sys.exit(0)
            except Exception as e:
                print(f"[!] Elevation notice: {e}")

def start_backend_server():
    """Runs FastAPI backend inside background daemon thread with disabled signal handlers."""
    try:
        from backend.main import app
        config = uvicorn.Config(
            app=app,
            host="127.0.0.1",
            port=AppConfig.PORT,
            log_level="warning",
            loop="asyncio"
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        server.run()
    except Exception as e:
        crash_log = WEBVIEW2_CACHE.parent / "SwitchGate_crash.log"
        try:
            with open(crash_log, "a", encoding="utf-8") as f:
                f.write(f"\n[{time.ctime()}] FastAPI Backend Exception: {e}\n")
                import traceback
                traceback.print_exc(file=f)
        except Exception:
            pass

def create_tray_icon_image():
    """Loads icon.ico or generates cyber icon for Windows system tray."""
    from PIL import Image, ImageDraw
    icon_path = BUNDLE_DIR / "assets" / "icon.ico"
    if not icon_path.exists():
        icon_path = BASE_DIR / "assets" / "icon.ico"
    if icon_path.exists():
        try:
            return Image.open(str(icon_path))
        except Exception:
            pass

    img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([4, 4, 60, 60], outline=(0, 245, 255, 255), width=4)
    draw.ellipse([18, 18, 46, 46], fill=(0, 245, 255, 220))
    return img

def cleanup_all():
    """Restores all system network settings, ARP tables, PAC proxy, and firewall on app exit."""
    try:
        from backend.core.activator import activator
        activator.deactivate_all()
    except Exception:
        pass
    try:
        from backend.native.network_engine import native_engine
        native_engine.flush_dns()
    except Exception:
        pass

def setup_tray(window):
    """Sets up PyStray system tray icon with quick actions."""
    try:
        import pystray
        
        def on_open(icon, item):
            window.show()
            window.restore()

        def on_toggle_pause(icon, item):
            current = db.get_setting("emergency_pause_active", "0") == "1"
            db.set_emergency_pause(not current)

        def on_quit(icon, item):
            icon.stop()
            cleanup_all()
            window.destroy()
            os._exit(0)

        menu = pystray.Menu(
            pystray.MenuItem("Open SwitchGate", on_open, default=True),
            pystray.MenuItem("🚨 Emergency Freeze (Dinner Time)", on_toggle_pause),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit SwitchGate", on_quit)
        )

        icon = pystray.Icon("SwitchGate", create_tray_icon_image(), "SwitchGate Gateway Controller", menu)
        threading.Thread(target=icon.run, daemon=True).start()
    except Exception as e:
        print(f"[Tray] System tray notice: {e}")

def wait_for_server(port: int, timeout: float = 25.0) -> bool:
    """Waits for FastAPI server to accept HTTP requests and return 200 OK."""
    start = time.time()
    url = f"http://127.0.0.1:{port}/"
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SwitchGate-Desktop"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False

def main():
    elevate_if_needed()

    import atexit
    atexit.register(cleanup_all)

    # 1. Start FastAPI Backend in background thread
    backend_thread = threading.Thread(target=start_backend_server, daemon=True, name="SwitchGate-FastAPI")
    backend_thread.start()
    
    # 2. Wait until FastAPI is 100% accepting requests (up to 25 seconds)
    wait_for_server(AppConfig.PORT, timeout=25.0)

    # 3. Create Native Windows Desktop Window (No External Browser Window!)
    app_url = f"http://127.0.0.1:{AppConfig.PORT}"
    
    webview.settings['ALLOW_DOWNLOADS'] = True
    webview.settings['ALLOW_FILE_URLS'] = True

    window = webview.create_window(
        title="SwitchGate - Network Gateway & Remote Control v2.0",
        url=app_url,
        width=1280,
        height=840,
        min_size=(1020, 680),
        background_color="#080b13",
        text_select=False,
        confirm_close=False
    )

    # 4. Initialize Tray
    setup_tray(window)

    # 5. Start Native EdgeChromium GUI event loop
    try:
        webview.start(gui="edgechromium", debug=False, private_mode=False, storage_path=str(WEBVIEW2_CACHE))
    except Exception as e:
        print(f"[!] Primary GUI start warning: {e}. Attempting fallback...")
        try:
            webview.start(debug=False, private_mode=False, storage_path=str(WEBVIEW2_CACHE))
        except Exception as e2:
            print(f"[!] GUI Fatal Error: {e2}")
    finally:
        cleanup_all()

if __name__ == "__main__":
    main()
