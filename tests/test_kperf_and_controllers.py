"""
SwitchGate - Comprehensive Verification Suite for kPerf & Network Controllers
"""
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.main import app
from backend.kperf.kperf_engine import kperf_engine
from backend.native.network_engine import native_engine
from backend.core.url_controller import url_controller
from backend.core.app_controller import app_controller
from backend.core.blocker import blocker

def run_all_tests():
    print("==================================================")
    print("   🚀 RUNNING SWITCHGATE kPERF VERIFICATION SUITE ")
    print("==================================================")

    # 1. kPerf Hypervisor
    print("[1/5] Testing kPerf Kernel Hypervisor...")
    kperf_engine.start()
    time.sleep(0.6)
    metrics = kperf_engine.get_metrics()
    assert metrics["kperf_status"] == "ACTIVE (Kernel Hypervisor)", f"Bad status: {metrics}"
    assert metrics["ring_buffer_capacity"] == 65536
    assert metrics["cpu_overhead"] == "0.0%"
    print(f"      kPerf Active! Shadows: {metrics['total_shadows_streamed']}, Pushed: {metrics['total_pushed']}")

    # 2. Native Win32 Gateway & DNS
    print("[2/5] Testing Native Gateway Resolution & DNS Flush...")
    gw_info = native_engine.resolve_real_gateway()
    assert "gateway_ip" in gw_info
    assert "local_ip" in gw_info
    dns_res = native_engine.flush_dns()
    assert dns_res is True
    print(f"      Gateway: {gw_info['gateway_ip']} ({gw_info['gateway_mac']}), Local: {gw_info['local_ip']}")

    # 3. TestClient API Endpoints
    print("[3/5] Testing REST API Endpoints...")
    client = TestClient(app)
    res_kperf = client.get("/api/kperf/metrics")
    assert res_kperf.status_code == 200
    assert res_kperf.json()["kperf_status"] == "ACTIVE (Kernel Hypervisor)"

    # 4. Website Controller (YouTube toggle & circuit breaker)
    print("[4/5] Testing Website Controller (YouTube Circuit Breaker)...")
    res_off = client.post("/api/websites/youtube.com/toggle", json={"action": "OFF"})
    assert res_off.status_code == 200
    assert res_off.json()["is_blocked"] is True

    res_list = client.get("/api/websites")
    assert res_list.status_code == 200
    sites = res_list.json()
    yt = next((s for s in sites if s["domain"] == "youtube.com"), None)
    assert yt is not None
    assert yt["is_blocked"] is True

    # Restore YouTube
    res_on = client.post("/api/websites/youtube.com/toggle", json={"action": "ON"})
    assert res_on.status_code == 200
    assert res_on.json()["is_blocked"] is False
    print("      YouTube Circuit Breaker Tested & Restored Successfully.")

    # 5. App Network Controller
    print("[5/5] Testing App Network Controller...")
    res_apps = client.get("/api/apps")
    assert res_apps.status_code == 200
    apps = res_apps.json()
    assert isinstance(apps, list)
    print(f"      Detected {len(apps)} live Windows processes with network sockets.")

    print("==================================================")
    print("   ✅ ALL 5 kPERF & NETWORK CONTROLLER TESTS PASSED! ")
    print("==================================================")

if __name__ == "__main__":
    run_all_tests()
