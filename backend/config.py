"""
SwitchGate - Core Configuration & Network Profile Settings
MSIX / Microsoft Store safe data directory resolution via Windows Shell API.
"""
import os
import sys
import tempfile
import psutil
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Bundle / Base directory (read-only, used for assets only)
# ─────────────────────────────────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = Path(sys._MEIPASS)
    BASE_DIR   = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent.parent
    BASE_DIR   = BUNDLE_DIR

# ─────────────────────────────────────────────────────────────────────────────
# MSIX-Safe Writable Data Directory
#
# Windows Shell API: SHGetFolderPath(CSIDL_LOCAL_APPDATA) always returns the
# REAL C:\Users\<user>\AppData\Local — it bypasses MSIX env var virtualization
# that causes PermissionError when writing inside WindowsApps.
# ─────────────────────────────────────────────────────────────────────────────

def _get_real_local_appdata() -> Path:
    """
    Uses Windows Shell32 API to get the true LocalAppData path.
    Immune to MSIX environment variable virtualization.
    Falls back through multiple safe options.
    """
    # ── Method 1: Windows Shell API (best — bypasses MSIX sandbox) ───────────
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            CSIDL_LOCAL_APPDATA = 0x001c
            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            ret = ctypes.windll.shell32.SHGetFolderPathW(
                None, CSIDL_LOCAL_APPDATA, None, 0, buf
            )
            if ret == 0 and buf.value:  # S_OK = 0
                p = Path(buf.value)
                if p.exists():
                    return p
        except Exception:
            pass

    # ── Method 2: Windows Registry (more reliable than env vars in MSIX) ─────
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            ) as key:
                val, _ = winreg.QueryValueEx(key, "Local AppData")
                p = Path(val)
                if p.exists():
                    return p
        except Exception:
            pass

    # ── Method 3: Environment variable (may be virtualized in MSIX) ──────────
    for env_key in ("LOCALAPPDATA", "APPDATA"):
        val = os.environ.get(env_key, "")
        if val:
            p = Path(val)
            # Reject if inside read-only system dirs
            pl = str(p).lower()
            if "windowsapps" not in pl and "program files" not in pl:
                return p

    # ── Method 4: User home ───────────────────────────────────────────────────
    try:
        home = Path.home()
        candidate = home / "AppData" / "Local"
        if candidate.exists():
            return candidate
        if home.exists():
            return home
    except Exception:
        pass

    # ── Method 5: System temp (always writable) ───────────────────────────────
    return Path(tempfile.gettempdir())


def _resolve_data_dir() -> Path:
    """Creates and returns a guaranteed writable data directory."""
    base = _get_real_local_appdata()
    data_dir = base / "SwitchGate" / "data"

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        # Verify write access
        test = data_dir / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        return data_dir
    except Exception:
        # Last resort: temp directory
        fallback = Path(tempfile.gettempdir()) / "SwitchGate" / "data"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


DATA_DIR           = _resolve_data_dir()
DB_PATH            = DATA_DIR / "switchgate.db"
ADBLOCK_CACHE_PATH = DATA_DIR / "adblock_domains.txt"

print(f"[Config] ✅ Data directory: {DATA_DIR}")

# ─────────────────────────────────────────────────────────────────────────────
# Native engine (lazy import — path resolution must happen first)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from backend.native.network_engine import native_engine as _native_engine
except Exception as _e:
    _native_engine = None
    print(f"[Config] Native engine import notice: {_e}")


class AppConfig:
    APP_NAME:    str  = "SwitchGate"
    APP_VERSION: str  = "2.0.1"
    HOST:        str  = "0.0.0.0"
    PORT:        int  = int(os.environ.get("SWITCHGATE_PORT", 8000))
    DEBUG:       bool = os.environ.get("SWITCHGATE_DEBUG", "false").lower() == "true"

    SCAN_INTERVAL_SECONDS:    int   = 6
    ARP_SCAN_TIMEOUT:         float = 1.5
    MOCK_DEVICES_FOR_TESTING: bool  = False

    INTERFACE_NAME: str = ""
    LOCAL_IP:       str = "127.0.0.1"
    GATEWAY_IP:     str = "192.168.1.1"
    GATEWAY_MAC:    str = "00:00:00:00:00:00"
    SUBNET_MASK:    str = "255.255.255.0"
    NETWORK_CIDR:   str = "192.168.1.0/24"
    HOST_MAC:       str = "00:00:00:00:00:00"

    ENABLE_ADBLOCK_SERVER: bool      = True
    DNS_PORT:              int       = int(os.environ.get("SWITCHGATE_DNS_PORT", 5353))
    UPSTREAM_DNS:          list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    BLOCK_METHOD:        str   = "ARP_SPOOF"
    ARP_POISON_INTERVAL: float = 0.5

    @classmethod
    def auto_detect_network(cls):
        """Auto-detects gateway, subnet, and interface. Psutil fallback on failure."""
        try:
            if _native_engine is None:
                raise RuntimeError("Native engine unavailable")
            gw = _native_engine.resolve_real_gateway()
            cls.GATEWAY_IP     = gw.get("gateway_ip",     cls.GATEWAY_IP)
            cls.GATEWAY_MAC    = gw.get("gateway_mac",    cls.GATEWAY_MAC)
            cls.LOCAL_IP       = gw.get("local_ip",       cls.LOCAL_IP)
            cls.HOST_MAC       = gw.get("host_mac",       cls.HOST_MAC)
            cls.NETWORK_CIDR   = gw.get("network_cidr",   cls.NETWORK_CIDR)
            cls.INTERFACE_NAME = gw.get("interface_name", cls.INTERFACE_NAME)
            print(
                f"[Config] Network: Gateway={cls.GATEWAY_IP} ({cls.GATEWAY_MAC}), "
                f"Local={cls.LOCAL_IP} ({cls.HOST_MAC}), Iface='{cls.INTERFACE_NAME}'"
            )
        except Exception as e:
            print(f"[Config] Native network detection failed ({e}), using psutil fallback.")
            try:
                import socket as _sock
                stats = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                for iface, stat in stats.items():
                    if not stat.isup:
                        continue
                    if iface.lower() in ("lo", "loopback pseudo-interface 1"):
                        continue
                    for addr in addrs.get(iface, []):
                        if addr.family == _sock.AF_INET and not addr.address.startswith("127."):
                            cls.LOCAL_IP       = addr.address
                            cls.INTERFACE_NAME = iface
                            base = addr.address.rsplit(".", 1)[0]
                            cls.NETWORK_CIDR   = f"{base}.0/24"
                            cls.GATEWAY_IP     = f"{base}.1"
                            break
                    if cls.LOCAL_IP != "127.0.0.1":
                        break
            except Exception as e2:
                print(f"[Config] Psutil fallback also failed: {e2}")


# Auto-detect on import
AppConfig.auto_detect_network()
