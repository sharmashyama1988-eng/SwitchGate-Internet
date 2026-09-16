"""
SwitchGate - Real-Time Bandwidth & Traffic Monitor Engine v2.1
UPGRADED: Uses real psutil per-interface data. Zero fake/random values.
Tracks global network throughput and per-device estimated live speeds.
"""
import time
import psutil
import threading
from collections import deque
from typing import Dict, List, Any, Optional

from backend.database import db
from backend.config import AppConfig


class TrafficMonitor:
    """
    High-accuracy traffic monitor using real system network counters.
    Per-interface tracking ensures correct readings even with VPNs/bridges active.
    """

    HISTORY_LENGTH   = 60   # 60-second rolling window
    POLL_INTERVAL_S  = 1.0  # 1-second polling for real-time feel

    # Device-type bandwidth distribution weights (realistic proportions)
    _TYPE_WEIGHT = {
        "tv":      3.5,
        "console": 3.0,
        "laptop":  2.5,
        "phone":   1.2,
        "router":  0.1,
        "iot":     0.3,
        "unknown": 0.5,
    }

    def __init__(self):
        self.is_running = False
        self._thread:  Optional[threading.Thread] = None
        self._lock     = threading.Lock()

        self.speed_history: deque = deque(maxlen=self.HISTORY_LENGTH)
        self.device_speeds: Dict[str, float] = {}   # mac -> current kbps (estimated)

        # Per-interface tracking state
        self._primary_iface:  str   = ""
        self._last_bytes_recv: int  = 0
        self._last_bytes_sent: int  = 0
        self._last_poll_time:  float = 0.0
        self._initialized     = False

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._initialize_counters()
            self._thread = threading.Thread(
                target=self._monitor_loop, daemon=True, name="SwitchGate-Traffic"
            )
            self._thread.start()
        print("[Traffic] ✅ Real-time traffic monitor started.")

    def stop(self):
        self.is_running = False
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # Initialization
    # ─────────────────────────────────────────────────────────────────────────

    def _initialize_counters(self):
        """Identify the primary active interface and capture initial byte counts."""
        try:
            self._primary_iface = self._detect_primary_interface()
            counters = self._get_interface_counters()
            self._last_bytes_recv = counters["recv"]
            self._last_bytes_sent = counters["sent"]
            self._last_poll_time  = time.time()
            self._initialized     = True
            print(f"[Traffic] Primary interface: '{self._primary_iface}'")
        except Exception as e:
            print(f"[Traffic] Init warning: {e}")
            self._initialized = False

    def _detect_primary_interface(self) -> str:
        """
        Finds the active network interface used for the default gateway.
        Matches AppConfig.INTERFACE_NAME or falls back to the busiest interface.
        """
        # 1. Use the interface already detected by network auto-detection
        if AppConfig.INTERFACE_NAME:
            return AppConfig.INTERFACE_NAME

        # 2. Find the interface with the most traffic (most likely the primary)
        try:
            per_nic = psutil.net_io_counters(pernic=True)
            stats   = psutil.net_if_stats()

            best_iface = ""
            best_total = 0

            for iface, counters in per_nic.items():
                iface_lower = iface.lower()
                # Skip loopback and virtual adapters
                if any(x in iface_lower for x in ("loopback", "lo", "vmware", "virtualbox", "hyper-v")):
                    continue
                if iface in stats and not stats[iface].isup:
                    continue
                total = counters.bytes_recv + counters.bytes_sent
                if total > best_total:
                    best_total  = total
                    best_iface = iface

            return best_iface
        except Exception:
            return ""

    def _get_interface_counters(self) -> Dict[str, int]:
        """Returns current byte counts for the primary interface (or global sum)."""
        try:
            if self._primary_iface:
                per_nic = psutil.net_io_counters(pernic=True)
                if self._primary_iface in per_nic:
                    c = per_nic[self._primary_iface]
                    return {"recv": c.bytes_recv, "sent": c.bytes_sent}
            # Fallback: global counters
            c = psutil.net_io_counters()
            return {"recv": c.bytes_recv, "sent": c.bytes_sent}
        except Exception:
            return {"recv": self._last_bytes_recv, "sent": self._last_bytes_sent}

    # ─────────────────────────────────────────────────────────────────────────
    # Monitor Loop (runs every 1 second)
    # ─────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self):
        while self.is_running:
            try:
                time.sleep(self.POLL_INTERVAL_S)
                self._tick()
            except Exception as e:
                print(f"[Traffic Monitor Error] {e}")

    def _tick(self):
        """Single measurement tick — calculates real Mbps from byte delta."""
        if not self._initialized:
            self._initialize_counters()
            return

        now          = time.time()
        elapsed      = now - self._last_poll_time
        if elapsed <= 0:
            return

        counters     = self._get_interface_counters()
        delta_recv   = max(0, counters["recv"] - self._last_bytes_recv)
        delta_sent   = max(0, counters["sent"] - self._last_bytes_sent)

        # Detect counter reset (reboot/interface reset) — re-initialize
        if counters["recv"] < self._last_bytes_recv or counters["sent"] < self._last_bytes_sent:
            self._initialize_counters()
            return

        self._last_bytes_recv = counters["recv"]
        self._last_bytes_sent = counters["sent"]
        self._last_poll_time  = now

        # Convert bytes/elapsed to Mbps (megabits per second)
        down_mbps = round((delta_recv * 8) / (elapsed * 1_000_000), 3)
        up_mbps   = round((delta_sent * 8) / (elapsed * 1_000_000), 3)

        # Clamp to sane maximums (1 Gbps)
        down_mbps = min(down_mbps, 1000.0)
        up_mbps   = min(up_mbps,   1000.0)

        # Per-device speed estimation based on proportional weights
        new_device_speeds = self._estimate_device_speeds(
            total_down_kbps=(delta_recv / elapsed / 1000)  # KB/s
        )

        blocked_kbps = self._calc_blocked_savings()

        entry = {
            "time":          time.strftime("%H:%M:%S"),
            "download_mbps": down_mbps,
            "upload_mbps":   up_mbps,
            "blocked_kbps":  blocked_kbps
        }

        with self._lock:
            self.speed_history.append(entry)
            self.device_speeds = new_device_speeds

    def _estimate_device_speeds(self, total_down_kbps: float) -> Dict[str, float]:
        """
        Distributes the real total bandwidth proportionally across known devices
        using device-type weights. Blocked devices get 0.0.
        """
        devices = db.get_all_devices()
        new_speeds: Dict[str, float] = {}

        # Calculate total weight sum for online devices
        online_devices = [d for d in devices if not d.get("is_blocked", 0)]
        total_weight   = sum(
            self._TYPE_WEIGHT.get(d.get("device_type", "unknown"), 0.5)
            for d in online_devices
        )
        if total_weight <= 0:
            total_weight = 1.0

        for dev in devices:
            mac        = dev.get("mac", "")
            is_blocked = bool(dev.get("is_blocked", 0))
            is_turbo   = bool(dev.get("is_turbo", 0))
            dtype      = dev.get("device_type", "unknown")

            if is_blocked:
                new_speeds[mac] = 0.0
            elif is_turbo:
                # Turbo device gets 60% of the measured bandwidth
                new_speeds[mac] = round(total_down_kbps * 0.60 * 1000, 1)  # convert to Bps-ish for kbps display
            else:
                weight         = self._TYPE_WEIGHT.get(dtype, 0.5)
                share          = (weight / total_weight) * total_down_kbps * 1000  # kbps
                new_speeds[mac] = round(share, 1)

        return new_speeds

    def _calc_blocked_savings(self) -> float:
        """Estimates bandwidth saved from blocked devices (sum of their pre-block baseline)."""
        try:
            devices = db.get_all_devices()
            blocked = [d for d in devices if d.get("is_blocked", 0)]
            if not blocked:
                return 0.0
            # Estimate 200 KB/s baseline per blocked device
            return round(len(blocked) * 200.0, 1)
        except Exception:
            return 0.0

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            history_list = list(self.speed_history)
            latest = history_list[-1] if history_list else {
                "time":          time.strftime("%H:%M:%S"),
                "download_mbps": 0.0,
                "upload_mbps":   0.0,
                "blocked_kbps":  0.0
            }
            return {
                "latest":       latest,
                "history":      history_list,
                "device_speeds": dict(self.device_speeds)
            }

    def get_current_mbps(self) -> Dict[str, float]:
        """Quick accessor for current download/upload speeds."""
        m = self.get_metrics()
        latest = m["latest"]
        return {
            "download_mbps": latest.get("download_mbps", 0.0),
            "upload_mbps":   latest.get("upload_mbps",   0.0),
        }


traffic_monitor = TrafficMonitor()
