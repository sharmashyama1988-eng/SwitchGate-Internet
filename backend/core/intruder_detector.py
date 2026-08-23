"""
SwitchGate - Intruder Alert & Auto-Quarantine Engine
Monitors network discovery for rogue devices and unauthorized Wi-Fi intruders.
"""
from typing import Dict, Any, List
from backend.database import db
from backend.core.blocker import blocker

class IntruderDetector:
    def __init__(self):
        pass

    def check_and_handle_new_device(self, mac: str, ip: str, vendor: str) -> Dict[str, Any]:
        """Called whenever network scanner detects a device."""
        mac = mac.lower().replace("-", ":")
        dev = db.get_device(mac)
        
        # If device is already banned -> enforce block
        if dev and dev.get("is_banned"):
            blocker.block_device(mac, ip)
            return {"status": "BANNED", "mac": mac}

        # Check if device is new (not in DB or not trusted)
        if not dev or dev.get("is_trusted") == 0:
            auto_quarantine = db.get_setting("auto_quarantine", "0") == "1"
            
            # Record alert
            db.record_intruder(mac, ip, vendor)

            if auto_quarantine:
                print(f"[Intruder Engine] 🚨 Auto-Quarantine Active: Blocking Unknown Device {mac} ({ip})")
                blocker.block_device(mac, ip)
                db.update_dual_switches(mac, left_on=False, right_on=False)
                return {"status": "QUARANTINED", "mac": mac, "ip": ip, "vendor": vendor}

            return {"status": "INTRUDER_ALERT", "mac": mac, "ip": ip, "vendor": vendor}

        return {"status": "TRUSTED", "mac": mac}

    def ban_device(self, mac: str) -> bool:
        dev = db.get_device(mac)
        if dev:
            blocker.block_device(mac, dev["ip"])
        return db.ban_intruder(mac)

    def trust_device(self, mac: str, friendly_name: str) -> bool:
        dev = db.get_device(mac)
        if dev and not db.get_setting("emergency_pause_active") == "1":
            blocker.unblock_device(mac, dev["ip"])
        return db.trust_intruder(mac, friendly_name)

intruder_detector = IntruderDetector()
