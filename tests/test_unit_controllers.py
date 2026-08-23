"""
SwitchGate - Unit Test Suite for kPerf & Network Controllers
"""
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.kperf.kperf_engine import kperf_engine
from backend.native.network_engine import native_engine
from backend.core.url_controller import url_controller
from backend.core.app_controller import app_controller
from backend.core.blocker import blocker

def run_tests():
    print("==================================================")
    print("   🚀 TESTING SWITCHGATE kPERF & CORE ENGINES     ")
    print("==================================================")

    # 1. kPerf Hypervisor
    print("[1/4] Testing kPerf Hypervisor & Ring Buffer...")
    kperf_engine.start()
    time.sleep(0.6)
    metrics = kperf_engine.get_metrics()
    assert metrics["kperf_status"] == "ACTIVE (Kernel Hypervisor)"
    assert metrics["ring_buffer_capacity"] == 65536
    assert metrics["cpu_overhead"] == "0.0%"
    print(f"      kPerf Status: {metrics['kperf_status']}")
    print(f"      Packet Shadows Streamed: {metrics['total_shadows_streamed']}")
    print(f"      Ring Buffer Capacity: {metrics['ring_buffer_capacity']} (Lock-Free SPSC)")

    # 2. Native Win32 Engine
    print("[2/4] Testing Native Win32 Gateway Resolution & DNS...")
    gw = native_engine.resolve_real_gateway()
    print(f"      Gateway IP: {gw['gateway_ip']}, MAC: {gw['gateway_mac']}, Local IP: {gw['local_ip']}")
    assert "gateway_ip" in gw
    assert native_engine.flush_dns() is True
    print("      Native DNS Cache Flush: SUCCESS")

    # 3. URL Controller & Circuit Breaker
    print("[3/4] Testing URL Controller YouTube Circuit Breaker...")
    url_controller.toggle_website("youtube.com", "OFF")
    sites = url_controller.get_live_websites()
    yt = next((s for s in sites if s["domain"] == "youtube.com"), None)
    assert yt is not None
    assert yt["is_blocked"] is True
    print(f"      YouTube Toggled OFF: {yt['is_blocked']} (Matrix domains + Sockets RST)")

    url_controller.toggle_website("youtube.com", "ON")
    sites = url_controller.get_live_websites()
    yt = next((s for s in sites if s["domain"] == "youtube.com"), None)
    assert yt is not None
    assert yt["is_blocked"] is False
    print(f"      YouTube Restored ON: {not yt['is_blocked']}")

    # 4. App Controller
    print("[4/4] Testing App Controller Process Network Inspection...")
    apps = app_controller.get_real_active_apps()
    print(f"      Detected {len(apps)} real running Windows apps with active sockets.")
    for a in apps[:3]:
        print(f"      - {a['friendly_name']} ({a['name']}): {a['connections_count']} conns, {a['total_mb']} MB")

    kperf_engine.stop()
    print("==================================================")
    print("   ✅ ALL UNIT TESTS COMPLETED WITH 100% SUCCESS! ")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
