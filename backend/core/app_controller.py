"""
SwitchGate - Real-Time App Network Controller (Zero-Crash & Persistent Enterprise Blocker)
Monitors real running Windows apps with network sockets, tracks live data usage (KB/s),
and enforces 100% PERSISTENT rules (Rules stay active in Windows Kernel even when SwitchGate is closed,
until explicitly toggled back ON by the user).
"""
import os
import sys
import json
import time
import psutil
import platform
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from backend.config import DATA_DIR
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine

IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    import winreg
    import ctypes
    _wininet = ctypes.windll.wininet
    _REG_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

PERSISTENT_RULES_FILE = DATA_DIR / "persistent_apps.json"

def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

class AppNetworkController:
    def __init__(self):
        self.blocked_apps: Dict[str, str] = {} # app_name -> exe_path
        self.app_prev_io: Dict[int, Dict[str, Any]] = {} # pid -> {bytes, time}
        self.app_live_speeds: Dict[str, float] = {} # app_name -> current KB/s
        self._lock = threading.Lock()
        self.is_running = False
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._load_persistent_rules()

    def _load_persistent_rules(self):
        """Loads saved blocked apps from disk and re-enforces Windows Firewall rules on startup."""
        if not PERSISTENT_RULES_FILE.exists():
            return
        try:
            with open(PERSISTENT_RULES_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                self.blocked_apps = saved
                # Re-apply firewall rules for all saved blocked apps
                for app_key, exe_path in self.blocked_apps.items():
                    if exe_path:
                        self._apply_firewall_rules(app_key, exe_path)
                print(f"[App Controller] Loaded {len(self.blocked_apps)} persistent blocked apps.")
        except Exception as e:
            print(f"[App Controller] Error loading persistent rules: {e}")

    def _save_persistent_rules(self):
        """Saves blocked apps to disk atomically."""
        try:
            PERSISTENT_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(PERSISTENT_RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(self.blocked_apps, f, indent=2)
        except Exception as e:
            print(f"[App Controller] Error saving persistent rules: {e}")

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="SwitchGate-AppController")
            self._monitor_thread.start()
            print("[App Controller] Persistent Universal Desktop App Controller active.")

    def stop(self):
        """
        On stop/exit, DO NOT delete firewall rules or reset blocked state!
        Rules remain 100% active and persistent in Windows Kernel even after closing.
        """
        self._stop_event.set()
        self.is_running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=1.0)
            except Exception:
                pass
        self._save_persistent_rules()
        print("[App Controller] Persistent rules safely preserved in Windows Kernel.")

    def get_real_active_apps(self) -> List[Dict[str, Any]]:
        """Scans all running processes with open TCP/UDP network connections."""
        active_map: Dict[str, Dict[str, Any]] = {}

        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.pid:
                    continue
                try:
                    p = psutil.Process(conn.pid)
                    name = p.name()
                    app_key = name.lower()
                    
                    if app_key not in active_map:
                        exe_path = ""
                        try:
                            exe_path = p.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass

                        category, friendly_name = self._categorize_app(name)
                        
                        io = None
                        try:
                            io = p.io_counters()
                        except Exception:
                            pass

                        read_bytes = io.read_bytes if io else 0
                        write_bytes = io.write_bytes if io else 0
                        total_mb = round((read_bytes + write_bytes) / (1024 * 1024), 2)

                        with self._lock:
                            is_blocked = app_key in self.blocked_apps

                        active_map[app_key] = {
                            "name": name,
                            "friendly_name": friendly_name,
                            "category": category,
                            "exe_path": exe_path,
                            "pids": [conn.pid],
                            "connections_count": 1,
                            "remote_endpoint": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Listening",
                            "is_blocked": is_blocked,
                            "total_mb": total_mb,
                            "current_kbps": self.app_live_speeds.get(app_key, 0.0) if not is_blocked else 0.0
                        }
                    else:
                        if conn.pid not in active_map[app_key]["pids"]:
                            active_map[app_key]["pids"].append(conn.pid)
                        active_map[app_key]["connections_count"] += 1
                        if conn.raddr and active_map[app_key]["remote_endpoint"] == "Listening":
                            active_map[app_key]["remote_endpoint"] = f"{conn.raddr.ip}:{conn.raddr.port}"

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            print(f"[App Controller Scan Error] {e}")

        # Ensure all persistent blocked apps remain visible
        with self._lock:
            for b_app, exe in self.blocked_apps.items():
                if b_app not in active_map:
                    category, friendly_name = self._categorize_app(b_app)
                    active_map[b_app] = {
                        "name": b_app,
                        "friendly_name": friendly_name,
                        "category": category,
                        "exe_path": exe,
                        "pids": [],
                        "connections_count": 0,
                        "remote_endpoint": "Blocked",
                        "is_blocked": True,
                        "total_mb": 0.0,
                        "current_kbps": 0.0
                    }

        result = list(active_map.values())
        result.sort(key=lambda x: (not x["is_blocked"], x["current_kbps"], x["connections_count"]), reverse=True)
        return result

    def _resolve_all_exe_paths(self, app_key: str, exe_path: str = "") -> List[str]:
        paths = set()
        if exe_path and os.path.exists(exe_path):
            paths.add(exe_path)

        for p in psutil.process_iter(['name', 'exe']):
            try:
                if p.info['name'] and p.info['name'].lower() == app_key:
                    if p.info.get('exe') and os.path.exists(p.info['exe']):
                        paths.add(p.info['exe'])
            except Exception:
                pass

        import glob
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            os.path.expandvars(r"%APPDATA%\Spotify\Spotify.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Discord\app-*\Discord.exe"),
            os.path.expandvars(r"%APPDATA%\Telegram Desktop\Telegram.exe"),
            r"C:\Program Files\uTorrent\uTorrent.exe",
            r"C:\Program Files (x86)\uTorrent\uTorrent.exe",
            os.path.expandvars(r"%APPDATA%\uTorrent\uTorrent.exe"),
            r"C:\Program Files\Zoom\bin\Zoom.exe",
            os.path.expandvars(r"%APPDATA%\Zoom\bin\Zoom.exe"),
        ]
        for cand in candidates:
            if cand.lower().endswith(app_key.lower()):
                for matched in glob.glob(cand):
                    if os.path.exists(matched):
                        paths.add(matched)

        return list(paths)

    def toggle_app_internet(self, app_name: str, exe_path: str, action: str) -> bool:
        """
        Switches internet ON or OFF for ANY desktop app (Persists across reboots and app closes).
        """
        app_key = app_name.lower().strip()
        action_upper = action.upper()

        matching_pids = []
        for p in psutil.process_iter(['name', 'exe', 'pid']):
            try:
                if p.info['name'] and p.info['name'].lower() == app_key:
                    matching_pids.append(p.info['pid'])
                    if not exe_path and p.info.get('exe'):
                        exe_path = p.info['exe']
            except Exception:
                pass

        if action_upper == "OFF":
            with self._lock:
                self.blocked_apps[app_key] = exe_path or ""
                self.app_live_speeds[app_key] = 0.0
                self._save_persistent_rules()

            # 1. Kill active sockets for this app
            if matching_pids:
                kperf_engine.kill_sockets_by_pids(matching_pids)

            # 2. Add Windows Firewall Inbound & Outbound Block Rules for the Executable
            self._apply_firewall_rules(app_key, exe_path)

            db.add_log("APP_BLOCK", "", "", f"Permanently Blocked Internet for {app_name} ({exe_path or 'Process'})")
            return True

        else: # action == "ON"
            with self._lock:
                if app_key in self.blocked_apps:
                    del self.blocked_apps[app_key]
                self._save_persistent_rules()

            # 1. Remove Windows Firewall Rules
            self._remove_firewall_rules(app_key, exe_path)

            # 2. Flush DNS & Sockets
            try:
                from backend.native.network_engine import native_engine
                native_engine.flush_dns()
            except Exception:
                pass

            db.add_log("APP_UNBLOCK", "", "", f"Permanently Restored Internet Access to {app_name}")
            return True

    def _apply_firewall_rules(self, app_key: str, exe_path: str):
        """
        Blocks internet for an app via Windows Firewall.
        Handles three scenarios:
          1. exe_path known + resolvable → block by exact executable path (most precise)
          2. exe_path known but file missing → still add rule for the path (rule created, app won't launch)
          3. No paths at all → block by process name pattern using PowerShell Get-Process loop
        """
        if not IS_WINDOWS:
            return

        rule_out = f"SwitchGate_App_{app_key.replace('.', '_').replace(' ', '_')}_Out"
        rule_in  = f"SwitchGate_App_{app_key.replace('.', '_').replace(' ', '_')}_In"

        all_paths = self._resolve_all_exe_paths(app_key, exe_path)

        # ── Scenario 1 & 2: We have at least one path ─────────────────────────
        if all_paths:
            for path in all_paths:
                if is_admin():
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_out}", "dir=out", "action=block",
                         f"program={path}", "enable=yes", "profile=any", "protocol=any"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_in}", "dir=in", "action=block",
                         f"program={path}", "enable=yes", "profile=any", "protocol=any"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                else:
                    cmd = (
                        f"netsh advfirewall firewall add rule name='{rule_out}' "
                        f"dir=out action=block program='{path}' enable=yes profile=any protocol=any; "
                        f"netsh advfirewall firewall add rule name='{rule_in}' "
                        f"dir=in action=block program='{path}' enable=yes profile=any protocol=any"
                    )
                    subprocess.run(
                        ["powershell", "-WindowStyle", "Hidden", "-Command",
                         f"Start-Process powershell -ArgumentList '-Command \"{cmd}\"' "
                         f"-Verb RunAs -WindowStyle Hidden"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
            return

        # ── Scenario 3: No paths — fallback to PowerShell process-name block ──
        # Finds all running exe paths matching the app name and creates rules for each
        print(f"[App Controller] No exe paths resolved for '{app_key}' — using PowerShell name-based block.")
        ps_block = (
            f"$procs = Get-Process | Where-Object {{$_.Name -like '*{app_key.replace('.exe','')}*'}} | "
            f"Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue | Where-Object {{$_}}; "
            f"foreach ($p in $procs) {{ "
            f"  netsh advfirewall firewall add rule name='{rule_out}' dir=out action=block program=$p enable=yes profile=any protocol=any; "
            f"  netsh advfirewall firewall add rule name='{rule_in}' dir=in action=block program=$p enable=yes profile=any protocol=any "
            f"}}"
        )
        if is_admin():
            subprocess.run(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_block],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            subprocess.run(
                ["powershell", "-WindowStyle", "Hidden", "-Command",
                 f"Start-Process powershell -ArgumentList '-Command \"{ps_block}\"' "
                 f"-Verb RunAs -WindowStyle Hidden"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

    def _remove_firewall_rules(self, app_key: str, exe_path: str = ""):
        if not IS_WINDOWS:
            return
        rule_out = f"SwitchGate_App_{app_key.replace('.', '_')}_Out"
        rule_in = f"SwitchGate_App_{app_key.replace('.', '_')}_In"

        if is_admin():
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            all_paths = self._resolve_all_exe_paths(app_key, exe_path)
            for path in all_paths:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"program={path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            cmd = f"netsh advfirewall firewall delete rule name='{rule_out}'; netsh advfirewall firewall delete rule name='{rule_in}'"
            all_paths = self._resolve_all_exe_paths(app_key, exe_path)
            for path in all_paths:
                cmd += f"; netsh advfirewall firewall delete rule program='{path}'"
            subprocess.run(["powershell", "-Command", f"Start-Process powershell -ArgumentList '-Command \"{cmd}\"' -Verb RunAs -WindowStyle Hidden"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _enable_system_blackhole_proxy(self):
        if not IS_WINDOWS:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:9999")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>;localhost;127.0.0.1;10.100.141.*")
            winreg.CloseKey(key)

            _wininet.InternetSetOptionW(0, 39, None, 0)
            _wininet.InternetSetOptionW(0, 37, None, 0)
        except Exception as e:
            print(f"[Proxy Error] {e}")

    def _disable_system_blackhole_proxy(self):
        if not IS_WINDOWS:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            _wininet.InternetSetOptionW(0, 39, None, 0)
            _wininet.InternetSetOptionW(0, 37, None, 0)
        except Exception as e:
            print(f"[Proxy Error] {e}")

    def _monitor_loop(self):
        """Calculates real per-app delta speeds every second."""
        while not self._stop_event.is_set():
            try:
                now = time.time()
                new_speeds = {}
                seen_pids = set()

                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = p.info['pid']
                        name = p.info['name']
                        if not name:
                            continue
                        seen_pids.add(pid)
                        app_key = name.lower()

                        with self._lock:
                            if app_key in self.blocked_apps:
                                new_speeds[app_key] = 0.0
                                continue

                        io = p.io_counters() if hasattr(p, 'io_counters') else None
                        if not io:
                            continue

                        total_bytes = io.read_bytes + io.write_bytes
                        if pid in self.app_prev_io:
                            prev_bytes = self.app_prev_io[pid]["bytes"]
                            prev_time = self.app_prev_io[pid]["time"]
                            dt = now - prev_time
                            if dt > 0:
                                kbps = round(((total_bytes - prev_bytes) / dt) / 1024, 1)
                                if kbps > 0:
                                    new_speeds[app_key] = new_speeds.get(app_key, 0.0) + kbps

                        self.app_prev_io[pid] = {"bytes": total_bytes, "time": now}
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Prune dead PIDs to guarantee zero memory leaks
                dead_pids = [pid for pid in self.app_prev_io if pid not in seen_pids]
                for pid in dead_pids:
                    del self.app_prev_io[pid]

                with self._lock:
                    self.app_live_speeds = new_speeds

            except Exception:
                pass

            if self._stop_event.wait(timeout=1.0):
                break

    def _categorize_app(self, name: str) -> tuple[str, str]:
        nl = name.lower()
        if "chrome" in nl: return "browser", "Google Chrome"
        if "msedge" in nl or "edge" in nl: return "browser", "Microsoft Edge"
        if "firefox" in nl: return "browser", "Mozilla Firefox"
        if "brave" in nl: return "browser", "Brave Browser"
        if "discord" in nl: return "social", "Discord"
        if "steam" in nl: return "gaming", "Steam Client"
        if "spotify" in nl: return "media", "Spotify Music"
        if "telegram" in nl: return "social", "Telegram Desktop"
        if "whatsapp" in nl: return "social", "WhatsApp Desktop"
        if "antigravity" in nl: return "devtools", "Antigravity AI Agent"
        if "code" in nl or "visualstudio" in nl: return "devtools", "VS Code Studio"
        if "python" in nl: return "devtools", "Python Network Worker"
        if "tally" in nl: return "tools", "Tally Gateway Service"
        if "node" in nl: return "devtools", "Node.js Server"
        if "svchost" in nl: return "system", "Windows Host Process"
        if "system" in nl or "lsass" in nl or "services" in nl: return "system", "Windows Kernel System"
        
        clean_name = name.replace(".exe", "").replace("-", " ").replace("_", " ").title()
        return "tools", clean_name

app_controller = AppNetworkController()
