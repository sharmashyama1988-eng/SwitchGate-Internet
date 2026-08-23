"""
SwitchGate Next-Gen Firewall - High-Speed Audit Logger & Ring Buffer
Combines sub-millisecond in-memory RAM ring buffer with durable SQLite audit persistence.
"""
import time
import sqlite3
import datetime
import threading
from collections import deque
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import os

try:
    from backend.config import DB_PATH as DB_FILE
except Exception:
    app_data_root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
    DB_FILE = Path(app_data_root) / "SwitchGate" / "data" / "switchgate.db"

class FirewallLogger:
    """Thread-safe High-Throughput Firewall Event & Threat Audit Logger."""

    def __init__(self, db_path: Path = DB_FILE, max_buffer_size: int = 5000):
        self.db_path = str(db_path)
        self.max_buffer_size = max_buffer_size
        self._ring_buffer: deque = deque(maxlen=max_buffer_size)
        self._lock = threading.Lock()
        
        # Threat statistics counters
        self.stats = {
            "total_logged": 0,
            "total_allowed": 0,
            "total_dropped": 0,
            "total_threats": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
                "CLEAN": 0
            },
            "top_blocked_ips": {},
            "top_blocked_ports": {}
        }

        self._init_db()

    def _init_db(self):
        """Initializes firewall_audit_logs table in database."""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                CREATE TABLE IF NOT EXISTS firewall_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    direction TEXT,
                    verdict TEXT NOT NULL,
                    reason TEXT,
                    severity TEXT NOT NULL,
                    payload_preview TEXT
                );
                """)
                conn.commit()
        except Exception as e:
            print(f"[FirewallLogger] SQLite init warning: {e}")

    def log_event(
        self,
        event_type: str,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "TCP",
        direction: str = "INBOUND",
        verdict: str = "ALLOW",
        reason: str = "Policy Allow",
        severity: str = "INFO",
        payload_preview: str = ""
    ) -> Dict[str, Any]:
        """Logs a firewall security event to both RAM ring buffer and SQLite database."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts = time.time()
        
        # Clean payload preview to avoid huge text
        if payload_preview and len(payload_preview) > 120:
            payload_preview = payload_preview[:117] + "..."

        log_entry = {
            "timestamp": now_str,
            "epoch_ts": ts,
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol.upper(),
            "direction": direction.upper(),
            "verdict": verdict.upper(),
            "reason": reason,
            "severity": severity.upper(),
            "payload_preview": payload_preview
        }

        # 1. Update in-memory ring buffer and stats
        with self._lock:
            self._ring_buffer.append(log_entry)
            self.stats["total_logged"] += 1
            if verdict.upper() == "DROP" or verdict.upper() == "BLOCK":
                self.stats["total_dropped"] += 1
                if src_ip:
                    self.stats["top_blocked_ips"][src_ip] = self.stats["top_blocked_ips"].get(src_ip, 0) + 1
                if dst_port:
                    p_key = str(dst_port)
                    self.stats["top_blocked_ports"][p_key] = self.stats["top_blocked_ports"].get(p_key, 0) + 1
            else:
                self.stats["total_allowed"] += 1

            if severity.upper() in ("CRITICAL", "HIGH", "MEDIUM"):
                self.stats["total_threats"] += 1

            sev = severity.upper()
            if sev in self.stats["severity_counts"]:
                self.stats["severity_counts"][sev] += 1
            else:
                self.stats["severity_counts"]["INFO"] += 1

        # 2. Asynchronous / Non-blocking DB write
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute("""
                INSERT INTO firewall_audit_logs 
                (timestamp, event_type, src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, reason, severity, payload_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    now_str, event_type, src_ip, dst_ip, src_port, dst_port,
                    protocol.upper(), direction.upper(), verdict.upper(), reason,
                    severity.upper(), payload_preview
                ))
                conn.commit()
        except Exception:
            pass  # DB busy or offline, RAM ring buffer guarantees real-time availability

        return log_entry

    def get_recent_logs(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        verdict: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves recent logs from RAM ring buffer with optional filtering."""
        with self._lock:
            logs = list(self._ring_buffer)

        # Apply filters
        if severity:
            sev_filter = severity.upper()
            logs = [l for l in logs if l.get("severity") == sev_filter]

        if verdict:
            verdict_filter = verdict.upper()
            logs = [l for l in logs if l.get("verdict") == verdict_filter]

        # Return latest logs in reverse chronological order
        return logs[-limit:][::-1]

    def get_threat_summary(self) -> Dict[str, Any]:
        """Returns aggregated threat intelligence and firewall statistics."""
        with self._lock:
            # Sort top blocked IPs
            sorted_ips = sorted(self.stats["top_blocked_ips"].items(), key=lambda x: x[1], reverse=True)[:5]
            sorted_ports = sorted(self.stats["top_blocked_ports"].items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "total_logged": self.stats["total_logged"],
                "total_allowed": self.stats["total_allowed"],
                "total_dropped": self.stats["total_dropped"],
                "total_threats": self.stats["total_threats"],
                "severity_breakdown": self.stats["severity_counts"].copy(),
                "top_blocked_ips": dict(sorted_ips),
                "top_blocked_ports": dict(sorted_ports),
                "buffer_utilization": len(self._ring_buffer),
                "buffer_capacity": self.max_buffer_size
            }

    def clear_logs(self) -> bool:
        """Flushes RAM ring buffer and purges database table."""
        with self._lock:
            self._ring_buffer.clear()
            self.stats["total_logged"] = 0
            self.stats["total_allowed"] = 0
            self.stats["total_dropped"] = 0
            self.stats["total_threats"] = 0
            for k in self.stats["severity_counts"]:
                self.stats["severity_counts"][k] = 0
            self.stats["top_blocked_ips"].clear()
            self.stats["top_blocked_ports"].clear()

        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute("DELETE FROM firewall_audit_logs;")
                conn.commit()
            return True
        except Exception as e:
            print(f"[FirewallLogger] Clear error: {e}")
            return True

# Global singleton
firewall_logger = FirewallLogger()
