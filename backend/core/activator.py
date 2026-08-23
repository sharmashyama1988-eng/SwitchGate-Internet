"""
SwitchGate - Universal System Activator
Warms up and launches all subsystems and engines simultaneously on startup with zero latency.
"""
import time
import threading

class SystemActivator:
    def __init__(self):
        self.is_activated = False
        self._lock = threading.Lock()

    def activate_all(self):
        with self._lock:
            if self.is_activated:
                return
            t0 = time.time()

            # 0. Silent Admin Power — must run FIRST before any privileged engine
            try:
                from backend.core.admin_power import admin_power
                admin_power.activate()
            except Exception as e:
                print(f"[Activator] AdminPower notice: {e}")

            # 1. Database & Config
            try:
                from backend.database import db
                from backend.config import AppConfig
                AppConfig.auto_detect_network()
                db.get_all_devices()
            except Exception as e:
                print(f"[Activator] DB/Config warmup: {e}")

            # 2. Start Core Engines (Isolated Error Boundaries)
            engines_to_start = [
                ("Blackhole Proxy", lambda: __import__("backend.core.blackhole_proxy", fromlist=["blackhole_server"]).blackhole_server.start()),
                ("kPerf Engine", lambda: __import__("backend.kperf.kperf_engine", fromlist=["kperf_engine"]).kperf_engine.start()),
                ("Blocker Engine", lambda: __import__("backend.core.blocker", fromlist=["blocker"]).blocker.start()),
                ("Network Scanner", lambda: __import__("backend.core.scanner", fromlist=["scanner"]).scanner.start_background_scan()),
                ("DNS Sinkhole", lambda: __import__("backend.core.dns_sinkhole", fromlist=["dns_sinkhole"]).dns_sinkhole.start()),
                ("Traffic Monitor", lambda: __import__("backend.core.traffic_monitor", fromlist=["traffic_monitor"]).traffic_monitor.start()),
                ("Smart Scheduler", lambda: __import__("backend.core.scheduler", fromlist=["scheduler"]).scheduler.start()),
                ("Ghost Detector", lambda: __import__("backend.core.ghost_detector", fromlist=["ghost_detector"]).ghost_detector.start()),
                ("App Controller", lambda: __import__("backend.core.app_controller", fromlist=["app_controller"]).app_controller.start()),
                ("URL Controller", lambda: __import__("backend.core.url_controller", fromlist=["url_controller"]).url_controller.start()),
                ("Next-Gen Firewall", lambda: __import__("firewall.firewall_controller", fromlist=["firewall_controller"]).firewall_controller.start()),
            ]

            for name, start_fn in engines_to_start:
                try:
                    start_fn()
                except Exception as e:
                    print(f"[Activator] Engine '{name}' startup warning: {e}")

            self.is_activated = True
            elapsed = round((time.time() - t0) * 1000, 2)
            print(f"[Activator] ⚡ All SwitchGate engines active in {elapsed}ms.")

    def deactivate_all(self):
        with self._lock:
            if not self.is_activated:
                return

            engines_to_stop = [
                ("Next-Gen Firewall", lambda: __import__("firewall.firewall_controller", fromlist=["firewall_controller"]).firewall_controller.stop()),
                ("Blocker Engine", lambda: __import__("backend.core.blocker", fromlist=["blocker"]).blocker.stop()),
                ("Network Scanner", lambda: __import__("backend.core.scanner", fromlist=["scanner"]).scanner.stop_background_scan()),
                ("DNS Sinkhole", lambda: __import__("backend.core.dns_sinkhole", fromlist=["dns_sinkhole"]).dns_sinkhole.stop()),
                ("Traffic Monitor", lambda: __import__("backend.core.traffic_monitor", fromlist=["traffic_monitor"]).traffic_monitor.stop()),
                ("Smart Scheduler", lambda: __import__("backend.core.scheduler", fromlist=["scheduler"]).scheduler.stop()),
                ("Ghost Detector", lambda: __import__("backend.core.ghost_detector", fromlist=["ghost_detector"]).ghost_detector.stop()),
                ("App Controller", lambda: __import__("backend.core.app_controller", fromlist=["app_controller"]).app_controller.stop()),
                ("URL Controller", lambda: __import__("backend.core.url_controller", fromlist=["url_controller"]).url_controller.stop()),
                ("kPerf Engine", lambda: __import__("backend.kperf.kperf_engine", fromlist=["kperf_engine"]).kperf_engine.stop()),
                ("Blackhole Proxy", lambda: __import__("backend.core.blackhole_proxy", fromlist=["blackhole_server"]).blackhole_server.stop()),
            ]

            for name, stop_fn in engines_to_stop:
                try:
                    stop_fn()
                except Exception as e:
                    print(f"[Activator] Engine '{name}' shutdown warning: {e}")

            self.is_activated = False

activator = SystemActivator()
