"""
SwitchGate - Comprehensive Test Suite v2.0
Validates Dual Switches, Smart Scheduler, Intruder Alert, Ghost Data Hunter, Emergency Pause and System Integration.
"""
import os
import sys
from pathlib import Path

# Ensure root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import AppConfig
from backend.database import db
from backend.core.scanner import scanner
from backend.core.blocker import blocker
from backend.core.dns_sinkhole import dns_sinkhole
from backend.core.traffic_monitor import traffic_monitor
from backend.core.scheduler import scheduler
from backend.core.ghost_detector import ghost_detector
from backend.core.intruder_detector import intruder_detector
from backend.core.system_integration import system_integration

def test_all():
    print("==================================================")
    print("   🧪 SWITCHGATE PRODUCTION VERIFICATION TEST     ")
    print("==================================================")

    # 1. Network Discovery
    print("\n[1/7] Testing Network Discovery & OUI Classification...")
    devices = scanner.scan_network()
    print(f"      Total devices indexed: {len(devices)}")
    assert len(devices) > 0, "Devices must be discovered/indexed"
    sample_mac = devices[0]["mac"]
    sample_ip = devices[0]["ip"]

    # 2. Dual-Switch Control
    print("\n[2/7] Testing Dual-Switch Engine...")
    # Left Switch OFF (Internet Pause)
    res = db.update_dual_switches(sample_mac, left_on=False, right_on=False)
    assert res["is_blocked"] == 1
    assert res["left_switch_on"] == 0
    print(f"      [OK] Left Switch OFF: {res['status_label']}")

    # Left Switch ON, Right Switch ON (High Priority)
    res = db.update_dual_switches(sample_mac, left_on=True, right_on=True)
    assert res["is_blocked"] == 0
    assert res["left_switch_on"] == 1
    print(f"      [OK] Dual Switch ON: {res['status_label']}")

    # 3. Turbo Focus Mode
    print("\n[3/7] Testing Turbo Focus Bandwidth Mode...")
    db.set_turbo_focus(sample_mac)
    dev = db.get_device(sample_mac)
    assert dev["is_turbo"] == 1
    print(f"      [OK] Turbo Focus activated on {dev['custom_name']}")
    db.set_turbo_focus(None)
    dev = db.get_device(sample_mac)
    assert dev["is_turbo"] == 0
    print("      [OK] Turbo Focus cleared successfully.")

    # 4. Emergency Pause (Dinner Time Freeze)
    print("\n[4/7] Testing One-Click Emergency Pause...")
    count = db.set_emergency_pause(True)
    print(f"      [OK] Emergency Pause frozen {count} devices.")
    assert db.get_setting("emergency_pause_active") == "1"
    db.set_emergency_pause(False)
    assert db.get_setting("emergency_pause_active") == "0"
    print("      [OK] Emergency Pause restored.")

    # 5. Intruder Alert & Auto-Quarantine
    print("\n[5/7] Testing Intruder Alert & Quarantine...")
    test_intruder_mac = "de:ad:be:ef:99:88"
    test_intruder_ip = "192.168.1.199"
    with db.get_connection() as conn:
        conn.execute("DELETE FROM devices WHERE mac = ?", (test_intruder_mac,))
        conn.execute("DELETE FROM intruder_alerts WHERE mac = ?", (test_intruder_mac,))
        conn.commit()
    alert = intruder_detector.check_and_handle_new_device(test_intruder_mac, test_intruder_ip, "Rogue Wi-Fi Attacker")
    assert alert["status"] in ["INTRUDER_ALERT", "QUARANTINED"]
    print(f"      [OK] Intruder detected and flagged: {alert}")

    # Test Ban
    intruder_detector.ban_device(test_intruder_mac)
    banned_dev = db.get_device(test_intruder_mac)
    assert banned_dev["is_banned"] == 1
    print("      [OK] Permanent Intruder Ban verified.")

    # 6. Ghost Data Leaks Tracker
    print("\n[6/7] Testing Ghost Data Leaks Tracker...")
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM ghost_leaks WHERE is_killed = 0")
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO ghost_leaks (mac, ip, domain, company, leak_kbps, detected_at, is_killed)
            VALUES ('PID:9999', '104.244.42.1', 'telemetry.test-tracker.com', 'Test Telemetry Service', 24.5, '2026-08-20 12:00:00', 0)
            """)
            conn.commit()
    leaks = ghost_detector.get_active_leaks()
    print(f"      Active ghost leaks detected: {len(leaks)}")
    assert len(leaks) > 0, "Expected at least 1 ghost leak sample"
    leak_id = leaks[0]["id"]
    leak_domain = leaks[0]["domain"]
    ghost_detector.kill_leak(leak_id)
    assert db.is_domain_blocked(leak_domain) is True
    print(f"      [OK] Ghost leak '{leak_domain}' vaporized and blocked.")

    # 7. Smart Time-Scheduler & System Integration
    print("\n[7/7] Testing Smart Time-Scheduler & Windows System...")
    rule_id = db.add_schedule(sample_mac, "Kids Bedtime", "22:00", "06:00", "ALL")
    assert rule_id > 0
    print("      [OK] Smart Scheduler rule registered.")
    is_win = system_integration.is_windows()
    print(f"      [OK] Windows System Platform Detected: {is_win}")

    print("\n==================================================")
    print("   🎉 ALL 7 PRODUCTION SYSTEM TESTS PASSED!       ")
    print("==================================================")

if __name__ == "__main__":
    test_all()
