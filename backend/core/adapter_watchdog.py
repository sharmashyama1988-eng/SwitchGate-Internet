"""
SwitchGate - Dynamic Network Adapter Watchdog
Monitors active network interfaces for state transitions (Wi-Fi drop, IP renewal,
Ethernet plug/unplug) and triggers automated socket and configuration re-binding.
"""
import time
import socket
import psutil
import threading
from typing import Optional, Set
from backend.config import AppConfig

class AdapterWatchdog:
    """Monitors Windows Network Adapter state transitions and triggers auto-recovery."""
    
    def __init__(self, check_interval: float = 3.0):
        self.check_interval = check_interval
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._last_active_iface: str = ""
        self._last_local_ip: str = ""
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._last_active_iface = AppConfig.INTERFACE_NAME
            self._last_local_ip = AppConfig.LOCAL_IP
            self._thread = threading.Thread(target=self._watch_loop, daemon=True, name="SwitchGate-AdapterWatchdog")
            self._thread.start()
            print("[Watchdog] 🛰️ Network Adapter Watchdog active.")

    def stop(self):
        self.is_running = False
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass

    def _watch_loop(self):
        while self.is_running:
            try:
                time.sleep(self.check_interval)
                current_ip = self._get_primary_ip()
                current_iface = AppConfig.INTERFACE_NAME

                # Detect IP or interface change
                if current_ip and current_ip != self._last_local_ip and current_ip != "127.0.0.1":
                    print(f"[Watchdog] 🔄 Network transition detected: {self._last_local_ip} -> {current_ip}. Re-binding network...")
                    AppConfig.auto_detect_network()
                    self._last_local_ip = AppConfig.LOCAL_IP
                    self._last_active_iface = AppConfig.INTERFACE_NAME
                    
                    # Refresh DNS sinkhole caches
                    try:
                        from backend.core.dns_sinkhole import dns_sinkhole
                        dns_sinkhole.clear_caches()
                    except Exception:
                        pass
                    
                    # Trigger an immediate scanner sweep
                    try:
                        from backend.core.scanner import scanner
                        threading.Thread(target=scanner.scan_network, daemon=True).start()
                    except Exception:
                        pass

            except Exception:
                pass

    def _get_primary_ip(self) -> str:
        """Lightweight non-blocking check of current primary route IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.2)
            # Connecting to a public IP doesn't send packets but selects the active routing interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

adapter_watchdog = AdapterWatchdog()
