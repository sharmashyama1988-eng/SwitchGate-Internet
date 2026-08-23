"""
SwitchGate - Universal System Activator
Launches ALL engines SIMULTANEOUSLY using parallel threads.
Zero sequential blocking — app UI shows instantly while engines warm up in background.
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

            # 0. Silent Admin Power — non-blocking background thread
            #    Token privilege escalation runs async so it doesn't delay startup
            try:
                from backend.core.admin_power import admin_power
                threading.Thread(
                    target=admin_power.activate,
                    daemon=True,
                    name="SwitchGate-AdminPower"
                ).start()
            except Exception as e:
                print(f"[Activator] AdminPower notice: {e}")

            # 1. Database & Config — must be synchronous (engines depend on it)
            try:
                from backend.database import db
                from backend.config import AppConfig
                # Network detection already cached from config.py import — just warm DB
                db.get_all_devices()
            except Exception as e:
                print(f"[Activator] DB warmup notice: {e}")

            # 2. Launch ALL engines in parallel — zero sequential waiting
            engines_to_start = [
                ("Blackhole Proxy",  lambda: __import__("backend.core.blackhole_proxy",  fromlist=["blackhole_server"]).blackhole_server.start()),
                ("kPerf Engine",     lambda: __import__("backend.kperf.kperf_engine",     fromlist=["kperf_engine"]).kperf_engine.start()),
                ("Blocker Engine",   lambda: __import__("backend.core.blocker",           fromlist=["blocker"]).blocker.start()),
                ("Network Scanner",  lambda: __import__("backend.core.scanner",           fromlist=["scanner"]).scanner.start_background_scan()),
                ("DNS Sinkhole",     lambda: __import__("backend.core.dns_sinkhole",      fromlist=["dns_sinkhole"]).dns_sinkhole.start()),
                ("Traffic Monitor",  lambda: __import__("backend.core.traffic_monitor",   fromlist=["traffic_monitor"]).traffic_monitor.start()),
                ("Smart Scheduler",  lambda: __import__("backend.core.scheduler",         fromlist=["scheduler"]).scheduler.start()),
                ("Ghost Detector",   lambda: __import__("backend.core.ghost_detector",    fromlist=["ghost_detector"]).ghost_detector.start()),
                ("App Controller",   lambda: __import__("backend.core.app_controller",    fromlist=["app_controller"]).app_controller.start()),
                ("URL Controller",   lambda: __import__("backend.core.url_controller",    fromlist=["url_controller"]).url_controller.start()),
                ("Next-Gen Firewall",lambda: __import__("firewall.firewall_controller",   fromlist=["firewall_controller"]).firewall_controller.start()),
            ]

            # Spawn one thread per engine — all start simultaneously
            threads = []
            for name, start_fn in engines_to_start:
                def _run(n=name, fn=start_fn):
                    try:
                        fn()
                    except Exception as e:
                        print(f"[Activator] Engine '{n}' startup notice: {e}")
                t = threading.Thread(target=_run, daemon=True, name=f"SwitchGate-{name}")
                t.start()
                threads.append(t)

            self.is_activated = True
            elapsed = round((time.time() - t0) * 1000, 2)
            print(f"[Activator] ⚡ All {len(threads)} engines launched in {elapsed}ms.")

    def deactivate_all(self):
        with self._lock:
            if not self.is_activated:
                return

            engines_to_stop = [
                ("Next-Gen Firewall", lambda: __import__("firewall.firewall_controller",  fromlist=["firewall_controller"]).firewall_controller.stop()),
                ("Blocker Engine",    lambda: __import__("backend.core.blocker",          fromlist=["blocker"]).blocker.stop()),
                ("Network Scanner",   lambda: __import__("backend.core.scanner",          fromlist=["scanner"]).scanner.stop_background_scan()),
                ("DNS Sinkhole",      lambda: __import__("backend.core.dns_sinkhole",     fromlist=["dns_sinkhole"]).dns_sinkhole.stop()),
                ("Traffic Monitor",   lambda: __import__("backend.core.traffic_monitor",  fromlist=["traffic_monitor"]).traffic_monitor.stop()),
                ("Smart Scheduler",   lambda: __import__("backend.core.scheduler",        fromlist=["scheduler"]).scheduler.stop()),
                ("Ghost Detector",    lambda: __import__("backend.core.ghost_detector",   fromlist=["ghost_detector"]).ghost_detector.stop()),
                ("App Controller",    lambda: __import__("backend.core.app_controller",   fromlist=["app_controller"]).app_controller.stop()),
                ("URL Controller",    lambda: __import__("backend.core.url_controller",   fromlist=["url_controller"]).url_controller.stop()),
                ("kPerf Engine",      lambda: __import__("backend.kperf.kperf_engine",    fromlist=["kperf_engine"]).kperf_engine.stop()),
                ("Blackhole Proxy",   lambda: __import__("backend.core.blackhole_proxy",  fromlist=["blackhole_server"]).blackhole_server.stop()),
            ]

            stop_threads = []
            for name, stop_fn in engines_to_stop:
                def _stop(n=name, fn=stop_fn):
                    try:
                        fn()
                    except Exception as e:
                        print(f"[Activator] Engine '{n}' shutdown notice: {e}")
                t = threading.Thread(target=_stop, daemon=True, name=f"SwitchGate-Stop-{name}")
                t.start()
                stop_threads.append(t)

            # Wait max 3 sec for clean shutdown
            for t in stop_threads:
                t.join(timeout=3.0)

            self.is_activated = False
            print("[Activator] All engines stopped.")

activator = SystemActivator()
