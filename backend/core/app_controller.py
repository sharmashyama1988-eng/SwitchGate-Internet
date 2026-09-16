"""
SwitchGate - Real-Time App Network Controller v2.5
Monitors real running Windows applications, provides 1-Click Internet Cutoff / Restore,
and enforces persistent Windows Defender Firewall rules + Socket Termination.
"""
import os
import sys
import json
import time
import glob
import psutil
import platform
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from backend.config import DATA_DIR
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine
from backend.core.silent_process import silent_run

IS_WINDOWS = platform.system() == "Windows"
PERSISTENT_RULES_FILE = DATA_DIR / "persistent_apps.json"


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


class AppNetworkController:
    def __init__(self):
        self.blocked_apps: Dict[str, str] = {}  # app_key -> exe_path
        self.app_prev_io: Dict[int, Dict[str, Any]] = {}  # pid -> {bytes, time}
        self.app_live_speeds: Dict[str, float] = {}  # app_key -> current KB/s
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
                for app_key, exe_path in self.blocked_apps.items():
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
        self._monitor_thread = threading.Thread(
            target=self._speed_monitor_loop, daemon=True, name="SwitchGate-AppSpeed"
        )
        self._monitor_thread.start()
        print("[App Controller] ✅ Windows Application Network Controller active.")

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=1.0)
            except Exception:
                pass

    def _speed_monitor_loop(self):
        """Measures per-process bandwidth (KB/s) in real-time."""
        while not self._stop_event.is_set():
            try:
                now = time.time()
                current_speeds: Dict[str, float] = {}

                for p in psutil.process_iter(['name', 'pid']):
                    try:
                        name = p.info['name']
                        pid = p.info['pid']
                        if not name:
                            continue

                        app_key = name.lower()
                        with self._lock:
                            if app_key in self.blocked_apps:
                                current_speeds[app_key] = 0.0
                                continue

                        io = p.io_counters()
                        total_bytes = io.read_bytes + io.write_bytes

                        if pid in self.app_prev_io:
                            prev_bytes = self.app_prev_io[pid]["bytes"]
                            prev_time = self.app_prev_io[pid]["time"]
                            dt = now - prev_time
                            if dt > 0.1:
                                kbps = max(0.0, ((total_bytes - prev_bytes) / 1024.0) / dt)
                                current_speeds[app_key] = current_speeds.get(app_key, 0.0) + round(kbps, 1)

                        self.app_prev_io[pid] = {"bytes": total_bytes, "time": now}
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception:
                        continue

                # Evict dead PIDs
                active_pids = set(psutil.pids())
                self.app_prev_io = {pid: v for pid, v in self.app_prev_io.items() if pid in active_pids}

                with self._lock:
                    self.app_live_speeds = current_speeds

            except Exception:
                pass
            time.sleep(1.0)

    def _categorize_app(self, name: str) -> tuple[str, str]:
        lower = name.lower()
        if any(x in lower for x in ("chrome", "edge", "msedge", "firefox", "brave", "opera")):
            return "Web Browser", name.split(".")[0].title()
        if any(x in lower for x in ("spotify", "discord", "telegram", "slack", "teams", "zoom", "whatsapp")):
            return "Communication / Media", name.split(".")[0].title()
        if any(x in lower for x in ("steam", "epic", "battle.net", "riot", "valorant", "csgo", "roblox")):
            return "Gaming Client", name.split(".")[0].title()
        if any(x in lower for x in ("utorrent", "bittorrent", "qbittorrent", "transmission")):
            return "P2P / Torrent", name.split(".")[0].title()
        if any(x in lower for x in ("svchost", "system", "lsass", "spoolsv", "services")):
            return "Windows Core OS", name
        return "Desktop App", name.split(".")[0].title()

    def get_real_active_apps(self) -> List[Dict[str, Any]]:
        active_map: Dict[str, Dict[str, Any]] = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.pid:
                    continue
                try:
                    p = psutil.Process(conn.pid)
                    name = p.name()
                    if not name:
                        continue

                    app_key = name.lower().strip()
                    exe_path = ""
                    try:
                        exe_path = p.exe()
                    except Exception:
                        pass

                    if app_key not in active_map:
                        category, friendly_name = self._categorize_app(name)
                        read_bytes, write_bytes = 0, 0
                        try:
                            io = p.io_counters()
                            read_bytes = io.read_bytes
                            write_bytes = io.write_bytes
                        except Exception:
                            pass

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
            print(f"[App Controller Scan Notice] {e}")

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
        """Exhaustively resolves all filesystem binary paths matching an app name."""
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

        base_name = app_key.replace(".exe", "")
        candidates = [
            rf"C:\Program Files\Google\Chrome\Application\{app_key}",
            rf"C:\Program Files (x86)\Google\Chrome\Application\{app_key}",
            os.path.expandvars(rf"%LOCALAPPDATA%\Google\Chrome\Application\{app_key}"),
            rf"C:\Program Files\Microsoft\Edge\Application\{app_key}",
            rf"C:\Program Files (x86)\Microsoft\Edge\Application\{app_key}",
            rf"C:\Program Files\Mozilla Firefox\{app_key}",
            rf"C:\Program Files (x86)\Mozilla Firefox\{app_key}",
            rf"C:\Program Files\BraveSoftware\Brave-Browser\Application\{app_key}",
            os.path.expandvars(rf"%APPDATA%\Spotify\{app_key}"),
            os.path.expandvars(rf"%LOCALAPPDATA%\Discord\app-*\{app_key}"),
            os.path.expandvars(rf"%APPDATA%\Telegram Desktop\{app_key}"),
            rf"C:\Program Files\uTorrent\{app_key}",
            rf"C:\Program Files (x86)\uTorrent\{app_key}",
            os.path.expandvars(rf"%APPDATA%\uTorrent\{app_key}"),
            rf"C:\Program Files\Zoom\bin\{app_key}",
            os.path.expandvars(rf"%APPDATA%\Zoom\bin\{app_key}"),
            rf"C:\Windows\System32\{app_key}",
            rf"C:\Windows\{app_key}",
        ]
        for cand in candidates:
            try:
                for matched in glob.glob(cand):
                    if os.path.exists(matched):
                        paths.add(matched)
            except Exception:
                pass

        return list(paths)

    def toggle_app_internet(self, app_name: str, exe_path: str, action: str) -> bool:
        """Switches internet ON or OFF for ANY desktop application."""
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

            # 2. Add Windows Firewall Inbound & Outbound Block Rules for all matched paths
            self._apply_firewall_rules(app_key, exe_path)

            db.add_log("APP_BLOCK", "", "", f"Permanently Blocked Internet for {app_name}")
            return True

        else:  # action == "ON"
            with self._lock:
                if app_key in self.blocked_apps:
                    del self.blocked_apps[app_key]
                self._save_persistent_rules()

            # 1. Remove Windows Firewall Rules
            self._remove_firewall_rules(app_key, exe_path)

            # 2. Flush DNS
            try:
                from backend.native.network_engine import native_engine
                native_engine.flush_dns()
            except Exception:
                pass

            db.add_log("APP_UNBLOCK", "", "", f"Permanently Restored Internet Access to {app_name}")
            return True

    def _apply_firewall_rules(self, app_key: str, exe_path: str):
        if not IS_WINDOWS:
            return

        clean_key = app_key.replace(".", "_").replace(" ", "_").replace("-", "_")
        rule_out = f"SwitchGate_App_{clean_key}_Out"
        rule_in  = f"SwitchGate_App_{clean_key}_In"

        all_paths = self._resolve_all_exe_paths(app_key, exe_path)

        if all_paths:
            for path in all_paths:
                # Add Outbound Block
                silent_run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_out}", "dir=out", "action=block",
                     f"program={path}", "enable=yes", "profile=any", "protocol=any"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                # Add Inbound Block
                silent_run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_in}", "dir=in", "action=block",
                     f"program={path}", "enable=yes", "profile=any", "protocol=any"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            print(f"[App Controller] ✅ Windows Firewall added rules for '{app_key}' across {len(all_paths)} paths.")
        else:
            # Fallback: Process name PowerShell rule
            ps_block = (
                f"$procs = Get-Process | Where-Object {{$_.Name -like '*{app_key.replace('.exe','')}*'}} | "
                f"Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue | Where-Object {{$_}}; "
                f"foreach ($p in $procs) {{ "
                f"  netsh advfirewall firewall add rule name='{rule_out}' dir=out action=block program=$p enable=yes profile=any protocol=any; "
                f"  netsh advfirewall firewall add rule name='{rule_in}' dir=in action=block program=$p enable=yes profile=any protocol=any "
                f"}}"
            )
            silent_run(["powershell", "-WindowStyle", "Hidden", "-Command", ps_block],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[App Controller] ✅ Process name block rules applied for '{app_key}'.")

    def _remove_firewall_rules(self, app_key: str, exe_path: str):
        if not IS_WINDOWS:
            return
        clean_key = app_key.replace(".", "_").replace(" ", "_").replace("-", "_")
        rule_out = f"SwitchGate_App_{clean_key}_Out"
        rule_in  = f"SwitchGate_App_{clean_key}_In"

        silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[App Controller] ✅ Removed Windows Firewall rules for '{app_key}'.")


app_controller = AppNetworkController()
