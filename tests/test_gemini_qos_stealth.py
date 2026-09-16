"""
SwitchGate - Verification Suite for Gemini Sentinel, QoS Turbo Engine & Zero-Trust Stealth Mode
"""
import sys
import os
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.main import app
from backend.core.gemini_sentinel import gemini_sentinel
from backend.core.qos_engine import qos_engine
from backend.core.stealth_engine import stealth_engine

def test_sentinel_qos_stealth_suite():
    print("==================================================")
    print("   🧠 TESTING GEMINI SENTINEL, QOS & STEALTH     ")
    print("==================================================")
    
    # 1. Stealth Engine Direct Test
    print("\n[1/5] Testing Stealth Engine & Camouflage...")
    initial_status = stealth_engine.get_status()
    assert "virtual_mac" in initial_status
    assert "cloaked_hostname" in initial_status

    # Toggle ON
    status_on = stealth_engine.toggle_stealth(True)
    assert status_on["enabled"] is True
    assert status_on["protection_level"] == "MAXIMUM_ZERO_TRUST"
    print(f"      [OK] Stealth Engine Verified (Virtual MAC: {status_on['virtual_mac']})")

    # 2. QoS Turbo Engine Direct Test
    print("\n[2/5] Testing QoS Turbo Engine & Profiles...")
    profiles = qos_engine.get_profiles()
    assert len(profiles) >= 5
    profile_ids = [p["id"] for p in profiles]
    assert "GAMING_TURBO" in profile_ids
    assert "STREAMING_4K" in profile_ids
    assert "DEVTOOLS_CLOUD" in profile_ids
    assert "STEALTH_CLOAK" in profile_ids
    assert "BALANCED" in profile_ids

    # Activate Gaming Turbo
    act_res = qos_engine.set_profile("GAMING_TURBO")
    assert act_res["id"] == "GAMING_TURBO"

    metrics = qos_engine.get_metrics()
    assert "ping_ms" in metrics
    assert "jitter_ms" in metrics
    assert metrics["active_profile"] == "GAMING_TURBO"
    print(f"      [OK] QoS Engine Verified (Active: {act_res['name']}, Ping: {metrics['ping_ms']}ms, Jitter: {metrics['jitter_ms']}ms)")

    # 3. Gemini Sentinel Status & Heuristic Analysis
    print("\n[3/5] Testing Gemini Sentinel Status & Heuristic Engine...")
    sentinel_status = gemini_sentinel.get_status()
    assert sentinel_status["status"] == "ONLINE"
    assert "engine_mode" in sentinel_status

    # Test direct synchronous gather & heuristic analysis
    net_state = gemini_sentinel._gather_network_state()
    assert "gateway_ip" in net_state
    assert "total_devices_count" in net_state
    
    analysis = gemini_sentinel._generate_heuristic_analysis(net_state)
    assert "threat_score" in analysis
    assert "threat_level" in analysis
    assert "summary" in analysis
    assert "findings" in analysis
    assert "remediations" in analysis
    assert isinstance(analysis["findings"], list)
    assert isinstance(analysis["remediations"], list)
    print(f"      [OK] AI Sentinel Diagnostics (Score: {analysis['threat_score']}, Level: {analysis['threat_level']}, Remediations: {len(analysis['remediations'])})")

    # 4. Zero-Click Instant Remediation Execution
    print("\n[4/5] Testing Zero-Click Remediation Execution...")
    # Test Domain Block Remediation
    res_rem_block = gemini_sentinel.execute_remediation("BLOCK_DOMAIN", {"domain": "rogue-telemetry-test.net"})
    assert res_rem_block["status"] == "SUCCESS"

    # Test QoS Change Remediation
    res_rem_qos = gemini_sentinel.execute_remediation("SET_QOS", {"profile": "STREAMING_4K"})
    assert res_rem_qos["status"] == "SUCCESS"
    assert qos_engine.get_active_profile()["id"] == "STREAMING_4K"

    # Test DNS Flush Remediation
    res_rem_dns = gemini_sentinel.execute_remediation("FLUSH_DNS", {})
    assert res_rem_dns["status"] == "SUCCESS"
    print("      [OK] Zero-Click Remediations (Domain Block, QoS Switch, DNS Flush) Executed Successfully.")

    # 5. REST API Integration via TestClient
    print("\n[5/5] Testing REST API Endpoints via TestClient...")
    client = TestClient(app)
    
    # Stealth endpoints
    res_s = client.get("/api/stealth/status")
    assert res_s.status_code == 200
    assert res_s.json()["enabled"] is True

    # QoS endpoints
    res_q = client.get("/api/qos/profiles")
    assert res_q.status_code == 200
    assert len(res_q.json()) >= 5

    # Sentinel status endpoint
    res_sentinel = client.get("/api/gemini-sentinel/status")
    assert res_sentinel.status_code == 200
    assert res_sentinel.json()["status"] == "ONLINE"

    print("      [OK] All REST API Endpoints (/api/stealth, /api/qos, /api/gemini-sentinel) Responded 200 OK.")

    print("\n==================================================")
    print("   🎉 ALL SENTINEL, QOS & STEALTH TESTS PASSED!   ")
    print("==================================================")

if __name__ == "__main__":
    test_sentinel_qos_stealth_suite()
