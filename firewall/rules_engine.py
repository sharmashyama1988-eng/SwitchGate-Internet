"""
SwitchGate Next-Gen Firewall - Dynamic Rules Engine
Supports Network Profiles (Public, Private, Domain), Inbound/Outbound Port & IP Filters, Whitelists & Blacklists.
"""
import os
import json
import ipaddress
import threading
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

try:
    from backend.config import DATA_DIR
except Exception:
    app_data_root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
    DATA_DIR = Path(app_data_root) / "SwitchGate" / "data"

RULES_FILE = DATA_DIR / "firewall_rules.json"

DEFAULT_RULES = {
    "enabled": True,
    "current_profile": "Private",
    "profiles": {
        "Public": {
            "name": "Public",
            "description": "Maximum Security for Public Wi-Fi / Coffee Shops / Airports. Aggressive Inbound Block.",
            "inbound_policy": "BLOCK_ALL_EXCEPT",
            "allowed_inbound_ports": [80, 443, 8000],
            "blocked_inbound_ports": [21, 22, 23, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080],
            "blocked_outbound_ports": [23, 445, 6667],
            "blocked_ips": ["192.168.1.100", "10.0.0.99"],
            "allowed_ips": []
        },
        "Private": {
            "name": "Private",
            "description": "Standard Home/Office LAN Security. Balances freedom with exploit protection.",
            "inbound_policy": "ALLOW_ALL_EXCEPT",
            "allowed_inbound_ports": [],
            "blocked_inbound_ports": [21, 23, 135, 445, 3389],
            "blocked_outbound_ports": [23, 6667],
            "blocked_ips": [],
            "allowed_ips": ["*"]
        },
        "Domain": {
            "name": "Domain",
            "description": "Enterprise Corporate Domain Network Security with Active Directory support.",
            "inbound_policy": "ALLOW_ALL_EXCEPT",
            "allowed_inbound_ports": [53, 80, 88, 135, 389, 443, 445, 636, 3268],
            "blocked_inbound_ports": [21, 23, 6667],
            "blocked_outbound_ports": [23, 6667],
            "blocked_ips": [],
            "allowed_ips": ["*"]
        }
    },
    "custom_rules": [
        {
            "id": "rule-smb-drop",
            "name": "Block SMB Ransomware Vector (EternalBlue)",
            "type": "PORT",
            "direction": "BOTH",
            "target": "445",
            "action": "DROP",
            "enabled": True
        },
        {
            "id": "rule-telnet-drop",
            "name": "Block Telnet Plaintext Exploit",
            "type": "PORT",
            "direction": "INBOUND",
            "target": "23",
            "action": "DROP",
            "enabled": True
        },
        {
            "id": "rule-rdp-drop",
            "name": "Block RDP Remote Desktop Brute-Force",
            "type": "PORT",
            "direction": "INBOUND",
            "target": "3389",
            "action": "DROP",
            "enabled": True
        },
        {
            "id": "rule-rpc-drop",
            "name": "Block Windows RPC Vulnerabilities",
            "type": "PORT",
            "direction": "INBOUND",
            "target": "135",
            "action": "DROP",
            "enabled": True
        },
        {
            "id": "rule-vnc-drop",
            "name": "Block VNC Remote Access",
            "type": "PORT",
            "direction": "INBOUND",
            "target": "5900",
            "action": "DROP",
            "enabled": True
        }
    ],
    "settings": {
        "auto_block_malware": True,
        "heuristic_scan": True,
        "netsh_sync": True,
        "max_audit_logs": 5000,
        "drop_invalid_packets": True
    }
}

class FirewallRulesEngine:
    """Thread-safe Next-Generation Dynamic Rules Engine."""
    
    def __init__(self, rules_file: Path = RULES_FILE):
        self.rules_file = rules_file
        self._lock = threading.Lock()
        self.rules = self.load_rules()

    def load_rules(self) -> Dict[str, Any]:
        """Loads firewall rules from JSON file with schema verification and default fallback."""
        with self._lock:
            if self.rules_file.exists():
                try:
                    with open(self.rules_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        # Merge defaults for any missing top-level keys
                        for k, v in DEFAULT_RULES.items():
                            if k not in data:
                                data[k] = v
                        return data
                except Exception as e:
                    print(f"[Firewall RulesEngine] Parse warning: {e}. Reverting to defaults.")
            
            # Write defaults if file does not exist
            self._save_rules_unlocked(DEFAULT_RULES)
            return json.loads(json.dumps(DEFAULT_RULES))

    def _save_rules_unlocked(self, rules_data: Dict[str, Any]):
        try:
            self.rules_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(rules_data, f, indent=2)
        except Exception as e:
            print(f"[Firewall RulesEngine] Save error: {e}")

    def save_rules(self, rules_data: Optional[Dict[str, Any]] = None):
        """Persists the current in-memory rule set to disk."""
        with self._lock:
            if rules_data is not None:
                self.rules = rules_data
            self._save_rules_unlocked(self.rules)

    # --- Master Enable / Disable ---
    def is_enabled(self) -> bool:
        return bool(self.rules.get("enabled", True))

    def set_enabled(self, enabled: bool) -> bool:
        with self._lock:
            self.rules["enabled"] = bool(enabled)
            self._save_rules_unlocked(self.rules)
        return self.rules["enabled"]

    def toggle_enabled(self) -> bool:
        with self._lock:
            self.rules["enabled"] = not self.rules.get("enabled", True)
            self._save_rules_unlocked(self.rules)
            return self.rules["enabled"]

    # --- Profile Management ---
    def get_current_profile(self) -> str:
        return self.rules.get("current_profile", "Private")

    def get_profiles(self) -> Dict[str, Any]:
        return self.rules.get("profiles", DEFAULT_RULES["profiles"])

    def get_current_profile_data(self) -> Dict[str, Any]:
        prof_name = self.get_current_profile()
        return self.get_profiles().get(prof_name, DEFAULT_RULES["profiles"]["Private"])

    def set_profile(self, profile_name: str) -> bool:
        """Switches active network profile (e.g. Public, Private, Domain)."""
        valid_profiles = self.rules.get("profiles", {}).keys()
        if profile_name in valid_profiles:
            with self._lock:
                self.rules["current_profile"] = profile_name
                self._save_rules_unlocked(self.rules)
            return True
        return False

    def update_profile_config(self, profile_name: str, config: Dict[str, Any]) -> bool:
        """Updates specific settings of a profile."""
        with self._lock:
            if profile_name in self.rules.get("profiles", {}):
                self.rules["profiles"][profile_name].update(config)
                self._save_rules_unlocked(self.rules)
                return True
        return False

    # --- IP Address Evaluation ---
    @staticmethod
    def _ip_matches(ip_to_check: str, pattern: str) -> bool:
        """Checks if an IP matches a single pattern (exact, wildcard, or CIDR)."""
        if pattern == "*" or pattern == "ANY":
            return True
        ip_to_check = ip_to_check.strip()
        pattern = pattern.strip()
        if ip_to_check == pattern:
            return True
        # Try CIDR subnet match (e.g. 192.168.1.0/24)
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(ip_to_check)
                return addr in net
            except Exception:
                pass
        return False

    def is_ip_blocked(self, ip: str, direction: str = "INBOUND") -> Tuple[bool, Optional[str]]:
        """Evaluates whether an IP is blocked by current profile policy or custom rules."""
        if not self.is_enabled():
            return False, None

        direction = direction.upper()
        profile_data = self.get_current_profile_data()
        
        # 1. Profile Whitelist check
        allowed_ips = profile_data.get("allowed_ips", [])
        if allowed_ips and allowed_ips != ["*"]:
            is_whitelisted = any(self._ip_matches(ip, p) for p in allowed_ips)
            if is_whitelisted:
                return False, None

        # 2. Profile Blocklist check
        blocked_ips = profile_data.get("blocked_ips", [])
        for b_ip in blocked_ips:
            if self._ip_matches(ip, b_ip):
                return True, f"Profile '{self.get_current_profile()}' Blacklisted IP: {b_ip}"

        # 3. Custom Rules check
        for r in self.rules.get("custom_rules", []):
            if not r.get("enabled", True):
                continue
            r_dir = r.get("direction", "BOTH").upper()
            if r_dir != "BOTH" and r_dir != direction:
                continue
            if r.get("type", "").upper() == "IP":
                target = str(r.get("target", ""))
                if self._ip_matches(ip, target):
                    action = r.get("action", "DROP").upper()
                    if action in ("DROP", "BLOCK", "REJECT"):
                        return True, f"Custom Rule [{r.get('name')}]: Blocked IP {target}"
                    elif action in ("ALLOW", "PASS"):
                        return False, None

        return False, None

    # --- Port Evaluation ---
    @staticmethod
    def _port_matches(port_to_check: int, pattern: str) -> bool:
        """Checks if a port matches a single pattern (number, range '8000-8080', or 'ANY')."""
        pattern = str(pattern).strip()
        if pattern == "*" or pattern.upper() == "ANY":
            return True
        if "-" in pattern:
            try:
                start_p, end_p = map(int, pattern.split("-"))
                return start_p <= port_to_check <= end_p
            except Exception:
                pass
        try:
            return int(pattern) == port_to_check
        except Exception:
            return False

    def is_port_blocked(self, port: int, direction: str = "INBOUND") -> Tuple[bool, Optional[str]]:
        """Evaluates whether a port is blocked by current profile policy or custom rules."""
        if not self.is_enabled():
            return False, None

        direction = direction.upper()
        profile_data = self.get_current_profile_data()

        if direction == "INBOUND":
            # Profile Inbound Policy (BLOCK_ALL_EXCEPT vs ALLOW_ALL_EXCEPT)
            policy = profile_data.get("inbound_policy", "ALLOW_ALL_EXCEPT")
            allowed_ports = profile_data.get("allowed_inbound_ports", [])
            blocked_ports = profile_data.get("blocked_inbound_ports", [])

            if policy == "BLOCK_ALL_EXCEPT":
                is_allowed = any(self._port_matches(port, p) for p in allowed_ports)
                if not is_allowed:
                    return True, f"Profile '{self.get_current_profile()}' Policy (BLOCK_ALL_EXCEPT): Port {port} not in allowlist"
            else:
                for bp in blocked_ports:
                    if self._port_matches(port, bp):
                        return True, f"Profile '{self.get_current_profile()}' Blocked Inbound Port: {bp}"

        elif direction == "OUTBOUND":
            blocked_out_ports = profile_data.get("blocked_outbound_ports", [])
            for bp in blocked_out_ports:
                if self._port_matches(port, bp):
                    return True, f"Profile '{self.get_current_profile()}' Blocked Outbound Port: {bp}"

        # Custom Rules check
        for r in self.rules.get("custom_rules", []):
            if not r.get("enabled", True):
                continue
            r_dir = r.get("direction", "BOTH").upper()
            if r_dir != "BOTH" and r_dir != direction:
                continue
            if r.get("type", "").upper() == "PORT":
                target = str(r.get("target", ""))
                # Support comma separated targets e.g. "80,443"
                for target_part in target.split(","):
                    if self._port_matches(port, target_part.strip()):
                        action = r.get("action", "DROP").upper()
                        if action in ("DROP", "BLOCK", "REJECT"):
                            return True, f"Custom Rule [{r.get('name')}]: Blocked Port {target}"
                        elif action in ("ALLOW", "PASS"):
                            return False, None

        return False, None

    # --- Protocol Evaluation ---
    def is_protocol_blocked(self, protocol: str, direction: str = "INBOUND") -> Tuple[bool, Optional[str]]:
        """Checks if a transport protocol (e.g. ICMP, GRE, IGMP) is blocked by custom rules."""
        if not self.is_enabled():
            return False, None

        protocol = protocol.upper().strip()
        direction = direction.upper()

        for r in self.rules.get("custom_rules", []):
            if not r.get("enabled", True):
                continue
            r_dir = r.get("direction", "BOTH").upper()
            if r_dir != "BOTH" and r_dir != direction:
                continue
            if r.get("type", "").upper() == "PROTOCOL":
                target = str(r.get("target", "")).upper().strip()
                if target in ("*", "ANY", protocol):
                    action = r.get("action", "DROP").upper()
                    if action in ("DROP", "BLOCK", "REJECT"):
                        return True, f"Custom Rule [{r.get('name')}]: Blocked Protocol {protocol}"
                    elif action in ("ALLOW", "PASS"):
                        return False, None

        return False, None

    # --- Custom Rule CRUD Operations ---
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        return self.rules.get("custom_rules", [])

    def add_custom_rule(
        self,
        name: str,
        rule_type: str,
        direction: str,
        target: str,
        action: str = "DROP",
        enabled: bool = True
    ) -> Dict[str, Any]:
        """Creates and appends a new rule to the firewall."""
        import uuid
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        new_rule = {
            "id": rule_id,
            "name": name.strip(),
            "type": rule_type.upper().strip(),
            "direction": direction.upper().strip(),
            "target": str(target).strip(),
            "action": action.upper().strip(),
            "enabled": bool(enabled)
        }
        with self._lock:
            self.rules.setdefault("custom_rules", []).append(new_rule)
            self._save_rules_unlocked(self.rules)
        return new_rule

    def update_custom_rule(self, rule_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Updates fields of an existing custom rule."""
        with self._lock:
            for r in self.rules.get("custom_rules", []):
                if r.get("id") == rule_id:
                    for k, v in kwargs.items():
                        if k in ("name", "type", "direction", "target", "action", "enabled"):
                            if isinstance(v, str):
                                r[k] = v.upper() if k in ("type", "direction", "action") else v.strip()
                            else:
                                r[k] = v
                    self._save_rules_unlocked(self.rules)
                    return r
        return None

    def delete_custom_rule(self, rule_id: str) -> bool:
        """Removes a custom rule by its ID."""
        with self._lock:
            rules = self.rules.get("custom_rules", [])
            new_rules = [r for r in rules if r.get("id") != rule_id]
            if len(new_rules) != len(rules):
                self.rules["custom_rules"] = new_rules
                self._save_rules_unlocked(self.rules)
                return True
        return False

    def toggle_custom_rule(self, rule_id: str) -> Optional[bool]:
        """Toggles the enabled status of a specific custom rule."""
        with self._lock:
            for r in self.rules.get("custom_rules", []):
                if r.get("id") == rule_id:
                    r["enabled"] = not r.get("enabled", True)
                    self._save_rules_unlocked(self.rules)
                    return r["enabled"]
        return None

    # --- Settings Management ---
    def get_settings(self) -> Dict[str, Any]:
        return self.rules.get("settings", DEFAULT_RULES["settings"])

    def update_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            settings = self.rules.setdefault("settings", DEFAULT_RULES["settings"].copy())
            settings.update(new_settings)
            self._save_rules_unlocked(self.rules)
            return settings

    def get_stats(self) -> Dict[str, Any]:
        """Returns rules engine summary metrics."""
        rules = self.get_custom_rules()
        enabled_count = sum(1 for r in rules if r.get("enabled", True))
        return {
            "enabled": self.is_enabled(),
            "current_profile": self.get_current_profile(),
            "total_custom_rules": len(rules),
            "active_custom_rules": enabled_count,
            "profile_summary": {
                name: {
                    "inbound_policy": p.get("inbound_policy"),
                    "blocked_inbound_ports_count": len(p.get("blocked_inbound_ports", [])),
                    "blocked_ips_count": len(p.get("blocked_ips", []))
                }
                for name, p in self.get_profiles().items()
            }
        }

# Global singleton
rules_engine = FirewallRulesEngine()
