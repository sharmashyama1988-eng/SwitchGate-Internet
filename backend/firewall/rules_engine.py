"""
SwitchGate Next-Gen Firewall - Dynamic Rules Engine
Supports Network Profiles (Public, Private, Domain), Inbound/Outbound Port & IP Filters.
"""
import os
import json
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
from backend.config import DATA_DIR

RULES_FILE = DATA_DIR / "firewall_rules.json"

DEFAULT_RULES = {
    "enabled": True,
    "current_profile": "Private",
    "profiles": {
        "Public": {
            "description": "High Security for Public Wi-Fi. Aggressive Inbound Blocking.",
            "inbound_policy": "BLOCK_ALL_EXCEPT",
            "allowed_inbound_ports": [80, 443, 8000],
            "blocked_inbound_ports": [21, 22, 23, 135, 137, 138, 139, 445, 3389, 8080],
            "blocked_ips": ["192.168.1.100"],
            "allowed_ips": []
        },
        "Private": {
            "description": "Standard Home/Office LAN Security. Balances Freedom & Protection.",
            "inbound_policy": "ALLOW_ALL_EXCEPT",
            "allowed_inbound_ports": [],
            "blocked_inbound_ports": [21, 23, 135, 445, 3389],
            "blocked_ips": [],
            "allowed_ips": ["*"]
        },
        "Domain": {
            "description": "Enterprise Corporate Domain Network Security.",
            "inbound_policy": "ALLOW_ALL_EXCEPT",
            "allowed_inbound_ports": [80, 443, 53, 389, 88],
            "blocked_inbound_ports": [21, 23],
            "blocked_ips": [],
            "allowed_ips": ["*"]
        }
    },
    "custom_rules": [
        {"id": "rule-1", "name": "Block Telnet Exploits", "type": "PORT", "direction": "INBOUND", "target": "23", "action": "DROP", "enabled": True},
        {"id": "rule-2", "name": "Block SMB Ransomware Vector", "type": "PORT", "direction": "BOTH", "target": "445", "action": "DROP", "enabled": True},
        {"id": "rule-3", "name": "Block RDP Brute-Force", "type": "PORT", "direction": "INBOUND", "target": "3389", "action": "DROP", "enabled": True}
    ]
}

class FirewallRulesEngine:
    def __init__(self, rules_file: Path = RULES_FILE):
        self.rules_file = rules_file
        self._lock = threading.Lock()
        self.rules = self.load_rules()

    def load_rules(self) -> Dict[str, Any]:
        with self._lock:
            if self.rules_file.exists():
                try:
                    with open(self.rules_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        # Merge defaults if keys missing
                        for k, v in DEFAULT_RULES.items():
                            if k not in data:
                                data[k] = v
                        return data
                except Exception as e:
                    print(f"[Firewall Rules] Parse warning: {e}. Using defaults.")
            self.save_rules(DEFAULT_RULES)
            return DEFAULT_RULES.copy()

    def save_rules(self, rules_data: Optional[Dict[str, Any]] = None):
        with self._lock:
            if rules_data is not None:
                self.rules = rules_data
            try:
                with open(self.rules_file, "w", encoding="utf-8") as f:
                    json.dump(self.rules, f, indent=2)
            except Exception as e:
                print(f"[Firewall Rules] Save error: {e}")

    def get_current_profile(self) -> str:
        return self.rules.get("current_profile", "Private")

    def set_profile(self, profile_name: str) -> bool:
        if profile_name in self.rules.get("profiles", {}):
            with self._lock:
                self.rules["current_profile"] = profile_name
                self.save_rules()
            return True
        return False

    def is_ip_blocked(self, ip: str, direction: str = "INBOUND") -> bool:
        profile = self.get_current_profile()
        profile_data = self.rules.get("profiles", {}).get(profile, {})
        blocked_ips = profile_data.get("blocked_ips", [])
        if ip in blocked_ips:
            return True
        
        # Check custom rules
        for r in self.rules.get("custom_rules", []):
            if r.get("enabled") and r.get("type") == "IP" and r.get("target") == ip:
                if r.get("action") == "DROP":
                    return True
        return False

    def is_port_blocked(self, port: int, direction: str = "INBOUND") -> bool:
        profile = self.get_current_profile()
        profile_data = self.rules.get("profiles", {}).get(profile, {})
        blocked_ports = profile_data.get("blocked_inbound_ports", [])
        
        if port in blocked_ports:
            return True

        if profile_data.get("inbound_policy") == "BLOCK_ALL_EXCEPT":
            allowed = profile_data.get("allowed_inbound_ports", [])
            if port not in allowed:
                return True

        for r in self.rules.get("custom_rules", []):
            if r.get("enabled") and r.get("type") == "PORT" and str(r.get("target")) == str(port):
                if r.get("action") == "DROP":
                    return True
        return False

    def add_custom_rule(self, name: str, rule_type: str, direction: str, target: str, action: str = "DROP") -> Dict[str, Any]:
        import uuid
        rule_id = f"rule-{uuid.uuid4().hex[:6]}"
        new_rule = {
            "id": rule_id,
            "name": name,
            "type": rule_type.upper(),
            "direction": direction.upper(),
            "target": target.strip(),
            "action": action.upper(),
            "enabled": True
        }
        with self._lock:
            self.rules.setdefault("custom_rules", []).append(new_rule)
            self.save_rules()
        return new_rule

    def delete_custom_rule(self, rule_id: str) -> bool:
        with self._lock:
            rules = self.rules.get("custom_rules", [])
            new_rules = [r for r in rules if r.get("id") != rule_id]
            if len(new_rules) != len(rules):
                self.rules["custom_rules"] = new_rules
                self.save_rules()
                return True
        return False

rules_engine = FirewallRulesEngine()
