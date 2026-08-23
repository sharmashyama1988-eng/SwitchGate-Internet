"""
SwitchGate - Database Layer & Persistence Engine (Optimized Concurrency)
"""
import sqlite3
import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional
from backend.config import DB_PATH

class Database:
    _instance = None

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)
        self._blocked_domains_cache: Optional[set] = None
        self.init_db()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = Database()
        return cls._instance

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Devices Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                custom_name TEXT NOT NULL,
                vendor TEXT DEFAULT 'Generic Device',
                device_type TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'ONLINE',
                is_blocked INTEGER DEFAULT 0,
                adblock_enabled INTEGER DEFAULT 1,
                is_turbo INTEGER DEFAULT 0,
                is_trusted INTEGER DEFAULT 1,
                is_banned INTEGER DEFAULT 0,
                left_switch_on INTEGER DEFAULT 1,
                right_switch_on INTEGER DEFAULT 1,
                status_label TEXT DEFAULT 'Connected | Active',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_bytes_sent INTEGER DEFAULT 0,
                total_bytes_recv INTEGER DEFAULT 0,
                current_kbps REAL DEFAULT 0.0
            );
            """)

            # 2. Activity Logs Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                mac TEXT,
                ip TEXT,
                details TEXT NOT NULL
            );
            """)

            # 3. Smart Time-Schedules Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                name TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                days TEXT DEFAULT 'ALL',
                is_active INTEGER DEFAULT 1,
                action TEXT DEFAULT 'BLOCK'
            );
            """)

            # 4. Ad-Purge Rules Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS adblock_rules (
                domain TEXT PRIMARY KEY,
                category TEXT DEFAULT 'ad',
                is_blocked INTEGER DEFAULT 1,
                hits INTEGER DEFAULT 0,
                added_at TEXT NOT NULL
            );
            """)

            # 5. Intruder Alerts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS intruder_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                vendor TEXT DEFAULT 'Unknown Device',
                detected_at TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING'
            );
            """)

            # 6. Ghost Leaks Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ghost_leaks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                company TEXT NOT NULL,
                leak_kbps REAL DEFAULT 0.0,
                detected_at TEXT NOT NULL,
                is_killed INTEGER DEFAULT 0
            );
            """)

            # 7. App Settings Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

            # Seed defaults
            defaults = [
                ("auto_quarantine", "0"),
                ("run_on_startup", "0"),
                ("minimize_to_tray", "1"),
                ("emergency_pause_active", "0"),
                ("turbo_focus_mac", "")
            ]
            for k, v in defaults:
                cursor.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)", (k, v))

            conn.commit()

        self._seed_default_adblock()

    def _seed_default_adblock(self):
        now = datetime.datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            seed_domains = [
                ("samsungads.com", "telemetry"),
                ("smetrics.samsung.com", "telemetry"),
                ("config.samsungcloudsolution.net", "telemetry"),
                ("lgtvonline.lge.com", "telemetry"),
                ("rdx2.lgtvsdp.com", "telemetry"),
                ("ibs.lgappstv.com", "telemetry"),
                ("scribe.logs.roku.com", "telemetry"),
                ("ads.roku.com", "ad"),
                ("doubleclick.net", "ad"),
                ("googleads.g.doubleclick.net", "ad"),
                ("pagead2.googlesyndication.com", "ad"),
                ("facebook.net", "tracker"),
                ("graph.instagram.com", "tracker"),
                ("telemetry.sdk.inmobi.com", "ad"),
                ("tracking.miui.com", "telemetry"),
                ("data.mistat.xiaomi.com", "telemetry"),
            ]
            for domain, cat in seed_domains:
                cursor.execute("INSERT OR IGNORE INTO adblock_rules (domain, category, is_blocked, hits, added_at) VALUES (?, ?, 1, 0, ?)", (domain, cat, now))

            conn.commit()

    # --- DEVICE OPERATIONS ---
    def upsert_device(self, mac: str, ip: str, vendor: str, device_type: str, suggested_name: str) -> Dict[str, Any]:
        now = datetime.datetime.now().isoformat()
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            
            if row:
                cursor.execute("UPDATE devices SET ip = ?, status = 'ONLINE', last_seen = ? WHERE mac = ?", (ip, now, mac))
            else:
                cursor.execute("""
                INSERT INTO devices 
                (mac, ip, custom_name, vendor, device_type, status, is_blocked, adblock_enabled, is_turbo, 
                 is_trusted, is_banned, left_switch_on, right_switch_on, status_label, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 'ONLINE', 0, 1, 0, 1, 0, 1, 1, 'Connected | Active', ?, ?)
                """, (mac, ip, suggested_name, vendor, device_type, now, now))
                
                # Activity log inside same transaction
                log_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                INSERT INTO activity_logs (timestamp, event_type, mac, ip, details)
                VALUES (?, 'DISCOVER', ?, ?, ?)
                """, (log_time, mac, ip, f"New device detected: {suggested_name} ({vendor})"))

            conn.commit()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            return dict(row) if row else {}

    def get_all_devices(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY is_banned ASC, is_blocked ASC, status ASC, ip ASC")
            return [dict(row) for row in cursor.fetchall()]

    def get_device(self, mac: str) -> Optional[Dict[str, Any]]:
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_dual_switches(self, mac: str, left_on: Optional[bool] = None, right_on: Optional[bool] = None) -> Dict[str, Any]:
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if not row:
                return {}
            dev = dict(row)

            new_left = left_on if left_on is not None else bool(dev["left_switch_on"])
            new_right = right_on if right_on is not None else bool(dev["right_switch_on"])

            is_blocked = not new_left
            if is_blocked:
                status_label = "Internet Access Paused" if dev.get("device_type") in ["phone", "laptop", "tablet"] else "Streaming Blocked"
            else:
                if new_right:
                    status_label = "Connected | High Priority" if dev.get("is_turbo") else "Connected | Active"
                else:
                    status_label = "Connected | Shield Off"

            cursor.execute("""
            UPDATE devices 
            SET left_switch_on = ?, right_switch_on = ?, is_blocked = ?, status_label = ?
            WHERE mac = ?
            """, (1 if new_left else 0, 1 if new_right else 0, 1 if is_blocked else 0, status_label, mac))

            log_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
            INSERT INTO activity_logs (timestamp, event_type, mac, ip, details)
            VALUES (?, 'SWITCH', ?, ?, ?)
            """, (log_time, mac, dev.get("ip", ""), f"{dev.get('custom_name', mac)} Switches: Left={new_left}, Right={new_right}"))

            conn.commit()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            updated_row = cursor.fetchone()
            return dict(updated_row) if updated_row else {}

    def update_device_toggle(self, mac: str, is_blocked: bool) -> bool:
        """Updates device blocked status and left switch state."""
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            status_label = "Internet Access Paused" if is_blocked else "Connected | Active"
            cursor.execute("""
            UPDATE devices 
            SET is_blocked = ?, left_switch_on = ?, status_label = ?
            WHERE mac = ?
            """, (1 if is_blocked else 0, 0 if is_blocked else 1, status_label, mac))
            conn.commit()
            return cursor.rowcount > 0

    def update_device_name(self, mac: str, new_name: str, device_type: Optional[str] = None) -> bool:
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if device_type:
                cursor.execute("UPDATE devices SET custom_name = ?, device_type = ? WHERE mac = ?", (new_name, device_type, mac))
            else:
                cursor.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (new_name, mac))
            conn.commit()
            return cursor.rowcount > 0

    def set_turbo_focus(self, target_mac: Optional[str]) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE devices SET is_turbo = 0")
            if target_mac:
                target_mac = target_mac.lower().replace("-", ":")
                cursor.execute("""
                UPDATE devices 
                SET is_turbo = 1, right_switch_on = 1, status_label = 'Connected | High Priority'
                WHERE mac = ?
                """, (target_mac,))
                cursor.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('turbo_focus_mac', ?)", (target_mac,))
            else:
                cursor.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('turbo_focus_mac', '')")
            conn.commit()
            return True

    def set_emergency_pause(self, active: bool) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('emergency_pause_active', ?)", ("1" if active else "0",))
            if active:
                cursor.execute("""
                UPDATE devices 
                SET is_blocked = 1, left_switch_on = 0, status_label = 'Internet Access Paused'
                WHERE device_type != 'router'
                """)
            else:
                cursor.execute("""
                UPDATE devices 
                SET is_blocked = 0, left_switch_on = 1, status_label = 'Connected | Active'
                WHERE is_banned = 0
                """)
            conn.commit()
            return cursor.rowcount

    # --- INTRUDER SECURITY ---
    def record_intruder(self, mac: str, ip: str, vendor: str) -> int:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM intruder_alerts WHERE mac = ? AND status = 'PENDING'", (mac,))
            if cursor.fetchone():
                return 0
            cursor.execute("""
            INSERT INTO intruder_alerts (mac, ip, vendor, detected_at, status)
            VALUES (?, ?, ?, ?, 'PENDING')
            """, (mac, ip, vendor, now))
            conn.commit()
            return cursor.lastrowid

    def get_pending_intruders(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM intruder_alerts WHERE status = 'PENDING' ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def ban_intruder(self, mac: str) -> bool:
        mac = mac.lower().replace("-", ":")
        now = datetime.datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE intruder_alerts SET status = 'BANNED' WHERE mac = ?", (mac,))
            
            # Check if device exists in devices table
            cursor.execute("SELECT ip FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if row:
                cursor.execute("""
                UPDATE devices 
                SET is_banned = 1, is_blocked = 1, left_switch_on = 0, right_switch_on = 0, status_label = 'BANNED INTRUDER'
                WHERE mac = ?
                """, (mac,))
            else:
                cursor.execute("""
                INSERT INTO devices 
                (mac, ip, custom_name, vendor, device_type, status, is_blocked, is_banned, is_trusted, left_switch_on, right_switch_on, status_label, first_seen, last_seen)
                VALUES (?, '0.0.0.0', 'Banned Rogue Device', 'Unauthorized Intruder', 'unknown', 'OFFLINE', 1, 1, 0, 0, 0, 'BANNED INTRUDER', ?, ?)
                """, (mac, now, now))
            conn.commit()
            return True

    def trust_intruder(self, mac: str, friendly_name: str) -> bool:
        mac = mac.lower().replace("-", ":")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE intruder_alerts SET status = 'APPROVED' WHERE mac = ?", (mac,))
            cursor.execute("""
            UPDATE devices 
            SET is_trusted = 1, is_banned = 0, is_blocked = 0, left_switch_on = 1, custom_name = ?
            WHERE mac = ?
            """, (friendly_name, mac))
            conn.commit()
            return True

    # --- GHOST DATA & LEAKS ---
    def get_ghost_leaks(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ghost_leaks WHERE is_killed = 0 ORDER BY leak_kbps DESC")
            return [dict(row) for row in cursor.fetchall()]

    def kill_ghost_leak(self, leak_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM ghost_leaks WHERE id = ?", (leak_id,))
            row = cursor.fetchone()
            if row:
                domain = row["domain"]
                now = datetime.datetime.now().isoformat()
                cursor.execute("INSERT OR REPLACE INTO adblock_rules (domain, category, is_blocked, hits, added_at) VALUES (?, 'ghost_tracker', 1, 0, ?)", (domain, now))
                cursor.execute("UPDATE ghost_leaks SET is_killed = 1 WHERE id = ?", (leak_id,))
                conn.commit()
                return True
            return False

    # --- SCHEDULES ---
    def get_schedules(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schedules ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def add_schedule(self, mac: str, name: str, start_time: str, end_time: str, days: str = "ALL") -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO schedules (mac, name, start_time, end_time, days, is_active, action)
            VALUES (?, ?, ?, ?, ?, 1, 'BLOCK')
            """, (mac, name, start_time, end_time, days))
            conn.commit()
            return cursor.lastrowid

    def delete_schedule(self, schedule_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
            conn.commit()
            return cursor.rowcount > 0

    # --- SETTINGS ---
    def get_setting(self, key: str, default: str = "") -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()

    # --- LOGS ---
    def add_log(self, event_type: str, mac: str, ip: str, details: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO activity_logs (timestamp, event_type, mac, ip, details)
                VALUES (?, ?, ?, ?, ?)
                """, (now, event_type, mac, ip, details))
                conn.commit()
        except Exception:
            pass

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- ADBLOCK RULES ---
    def get_adblock_rules(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM adblock_rules ORDER BY hits DESC, added_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def _get_blocked_domains_set(self) -> set:
        if self._blocked_domains_cache is not None:
            return self._blocked_domains_cache
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT domain FROM adblock_rules WHERE is_blocked = 1")
                self._blocked_domains_cache = {row["domain"].lower() for row in cursor.fetchall()}
        except Exception:
            return set()
        return self._blocked_domains_cache

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        domain = domain.lower().strip().rstrip(".")
        blocked_set = self._get_blocked_domains_set()
        
        if domain in blocked_set:
            return True
        
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent_domain = ".".join(parts[i:])
            if parent_domain in blocked_set:
                return True
        return False

    def add_adblock_rule(self, domain: str, category: str = "custom") -> bool:
        domain = domain.lower().strip().rstrip(".")
        now = datetime.datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO adblock_rules (domain, category, is_blocked, hits, added_at) VALUES (?, ?, 1, 0, ?)", (domain, category, now))
            conn.commit()
        if self._blocked_domains_cache is not None:
            self._blocked_domains_cache.add(domain)
        return True

    def delete_adblock_rule(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM adblock_rules WHERE domain = ?", (domain,))
            conn.commit()
            count = cursor.rowcount
        if self._blocked_domains_cache is not None:
            self._blocked_domains_cache.discard(domain)
        return count > 0

db = Database.get_instance()
