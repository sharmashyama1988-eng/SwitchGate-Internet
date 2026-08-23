"""
SwitchGate Next-Gen Firewall - Deep Packet Inspection (DPI) & Packet Filter Engine
Evaluates network tuples (IP, Port, Protocol, Payload) against security profiles, custom ACLs, and malware scanners.
"""
import time
from typing import Dict, Any, Optional, Union

from firewall.rules_engine import rules_engine, FirewallRulesEngine
from firewall.antivirus import antivirus, AntivirusScanner
from firewall.firewall_logger import firewall_logger, FirewallLogger

class PacketFilter:
    """Next-Generation Deep Packet Inspection (DPI) & Threat Filtering Engine."""

    def __init__(
        self,
        engine: Optional[FirewallRulesEngine] = None,
        scanner: Optional[AntivirusScanner] = None,
        logger: Optional[FirewallLogger] = None
    ):
        self.rules_engine = engine or rules_engine
        self.antivirus = scanner or antivirus
        self.logger = logger or firewall_logger
        self.total_packets_inspected = 0
        self.total_packets_dropped = 0
        self.total_packets_allowed = 0

    def inspect_packet(
        self,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 0,
        dst_port: int = 80,
        protocol: str = "TCP",
        direction: str = "INBOUND",
        payload: Union[bytes, str, None] = None,
        log_decision: bool = True
    ) -> Dict[str, Any]:
        """
        Performs Deep Packet Inspection on a packet or socket connection tuple.
        Returns the security verdict (ALLOW or DROP), reason, severity, and threat metadata.
        """
        self.total_packets_inspected += 1
        direction = direction.upper().strip()
        protocol = protocol.upper().strip()
        now_ts = time.time()

        # 1. Firewall Master Switch Check
        if not self.rules_engine.is_enabled():
            verdict = "ALLOW"
            reason = "Firewall Subsystem Disabled (Bypass Mode)"
            sev = "INFO"
            self.total_packets_allowed += 1
            res = {
                "verdict": verdict,
                "allowed": True,
                "reason": reason,
                "severity": sev,
                "rule_matched": "GLOBAL_BYPASS",
                "threat_info": None,
                "timestamp": now_ts
            }
            if log_decision:
                self.logger.log_event("PACKET_BYPASS", src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, reason, sev)
            return res

        # 2. Antivirus & Deep Payload Heuristic Inspection
        threat_info = None
        if payload:
            scan_res = self.antivirus.scan_payload(payload, src_ip=src_ip, dst_port=dst_port)
            if scan_res.get("is_threat"):
                verdict = "DROP"
                reason = f"Malware/Exploit Neutralized: {scan_res.get('threat_name')} ({scan_res.get('threat_type')})"
                sev = scan_res.get("severity", "CRITICAL")
                self.total_packets_dropped += 1
                
                # Payload preview snippet
                snippet = str(payload)[:80] if isinstance(payload, str) else payload[:80].decode("latin-1", errors="ignore")
                
                if log_decision:
                    self.logger.log_event(
                        "THREAT_DROPPED", src_ip, dst_ip, src_port, dst_port,
                        protocol, direction, verdict, reason, sev, snippet
                    )
                return {
                    "verdict": verdict,
                    "allowed": False,
                    "reason": reason,
                    "severity": sev,
                    "rule_matched": f"AV_SIGNATURE_{scan_res.get('threat_type')}",
                    "threat_info": scan_res,
                    "timestamp": now_ts
                }

        # 3. Protocol Blocking Check
        proto_blocked, proto_reason = self.rules_engine.is_protocol_blocked(protocol, direction)
        if proto_blocked:
            verdict = "DROP"
            sev = "MEDIUM"
            self.total_packets_dropped += 1
            if log_decision:
                self.logger.log_event("PROTOCOL_BLOCKED", src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, proto_reason or "Protocol Blocked", sev)
            return {
                "verdict": verdict,
                "allowed": False,
                "reason": proto_reason or f"Protocol {protocol} blocked",
                "severity": sev,
                "rule_matched": "PROTOCOL_RULE",
                "threat_info": None,
                "timestamp": now_ts
            }

        # 4. IP Address Check (Source & Destination)
        check_ip = src_ip if direction == "INBOUND" else dst_ip
        ip_blocked, ip_reason = self.rules_engine.is_ip_blocked(check_ip, direction)
        if ip_blocked:
            verdict = "DROP"
            sev = "HIGH"
            self.total_packets_dropped += 1
            if log_decision:
                self.logger.log_event("IP_BLOCKED", src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, ip_reason or "IP Blocked", sev)
            return {
                "verdict": verdict,
                "allowed": False,
                "reason": ip_reason or f"IP {check_ip} is blocked",
                "severity": sev,
                "rule_matched": "IP_POLICY_RULE",
                "threat_info": None,
                "timestamp": now_ts
            }

        # 5. Port Filter Check
        check_port = dst_port if direction == "INBOUND" else dst_port
        port_blocked, port_reason = self.rules_engine.is_port_blocked(check_port, direction)
        if port_blocked:
            verdict = "DROP"
            sev = "HIGH" if check_port in (21, 23, 135, 445, 3389) else "MEDIUM"
            self.total_packets_dropped += 1
            if log_decision:
                self.logger.log_event("PORT_BLOCKED", src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, port_reason or f"Port {check_port} Blocked", sev)
            return {
                "verdict": verdict,
                "allowed": False,
                "reason": port_reason or f"Port {check_port} is blocked by profile policy",
                "severity": sev,
                "rule_matched": "PORT_POLICY_RULE",
                "threat_info": None,
                "timestamp": now_ts
            }

        # 6. Default Allow Decision
        verdict = "ALLOW"
        reason = f"Profile '{self.rules_engine.get_current_profile()}' Policy: Allowed Traffic"
        sev = "CLEAN"
        self.total_packets_allowed += 1
        if log_decision:
            self.logger.log_event("PACKET_ALLOWED", src_ip, dst_ip, src_port, dst_port, protocol, direction, verdict, reason, sev)

        return {
            "verdict": verdict,
            "allowed": True,
            "reason": reason,
            "severity": sev,
            "rule_matched": "PROFILE_DEFAULT_ALLOW",
            "threat_info": None,
            "timestamp": now_ts
        }

# Global singleton
packet_filter = PacketFilter()
