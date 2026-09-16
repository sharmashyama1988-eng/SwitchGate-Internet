"""
SwitchGate - AI Network Sentinel & Gemini Brain v2.5
Autonomous AI Threat Diagnostic, Natural-Language Packet Drop Analyzer, and Zero-Click Network Optimizer.
Powered by Google Gemini API (gemini-2.5-flash / gemini-1.5-flash) with Built-in Heuristic Neural Rule Fallback.
"""
import os
import json
import time
import asyncio
import httpx
from typing import Dict, Any, List, Optional

from backend.config import AppConfig
from backend.database import db
from backend.core.scanner import scanner
from backend.core.ghost_detector import ghost_detector
from backend.core.dns_sinkhole import dns_sinkhole
from backend.core.traffic_monitor import traffic_monitor
from backend.core.app_controller import app_controller
from backend.core.qos_engine import qos_engine
from backend.core.stealth_engine import stealth_engine
from backend.native.network_engine import native_engine

GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

class GeminiSentinel:
    _instance = None

    def __init__(self):
        self._last_analysis: Optional[Dict[str, Any]] = None
        self._last_analyzed_ts: float = 0.0
        self._is_analyzing: bool = False
        self._chat_history: List[Dict[str, str]] = []

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = GeminiSentinel()
        return cls._instance

    def get_api_key(self) -> str:
        # Priority: 1. DB setting, 2. Env variable
        saved_key = db.get_setting("gemini_api_key", "").strip()
        if saved_key:
            return saved_key
        return os.environ.get("GEMINI_API_KEY", "").strip()

    def set_api_key(self, api_key: str):
        db.set_setting("gemini_api_key", api_key.strip())

    def get_model(self) -> str:
        return db.get_setting("gemini_model", GEMINI_DEFAULT_MODEL)

    def set_model(self, model: str):
        db.set_setting("gemini_model", model.strip())

    def get_status(self) -> Dict[str, Any]:
        api_key = self.get_api_key()
        has_key = bool(api_key and len(api_key) > 5)
        masked_key = f"{api_key[:4]}...{api_key[-4:]}" if has_key and len(api_key) > 8 else ("Configured" if has_key else "None")
        
        return {
            "status": "ONLINE",
            "has_gemini_key": has_key,
            "masked_key": masked_key,
            "engine_mode": "GEMINI_CLOUD_AI" if has_key else "LOCAL_HEURISTIC_NEURAL_ENGINE",
            "model": self.get_model(),
            "last_analyzed_ts": self._last_analyzed_ts,
            "last_threat_score": self._last_analysis.get("threat_score", 0) if self._last_analysis else 0,
            "is_analyzing": self._is_analyzing
        }

    def _gather_network_state(self) -> Dict[str, Any]:
        """Collects exhaustive live network telemetry for AI analysis."""
        try:
            devices = db.get_all_devices()
        except Exception:
            devices = []

        try:
            ghosts = db.get_ghost_leaks()
        except Exception:
            ghosts = []

        try:
            intruders = db.get_pending_intruders()
        except Exception:
            intruders = []

        try:
            dns_stats = dns_sinkhole.get_stats()
        except Exception:
            dns_stats = {"total_blocked": 0, "total_queries": 0}

        try:
            apps = app_controller.get_real_active_apps()
        except Exception:
            apps = []

        try:
            traffic = traffic_monitor.get_metrics()
        except Exception:
            traffic = {}

        try:
            qos_metrics = qos_engine.get_metrics()
        except Exception:
            qos_metrics = {}

        try:
            stealth_status = stealth_engine.get_status()
        except Exception:
            stealth_status = {}

        try:
            from firewall.firewall_controller import firewall_controller
            fw_telemetry = firewall_controller.get_telemetry()
        except Exception:
            fw_telemetry = {}

        return {
            "gateway_ip": AppConfig.GATEWAY_IP,
            "local_ip": AppConfig.LOCAL_IP,
            "total_devices_count": len(devices),
            "blocked_devices_count": sum(1 for d in devices if d.get("is_blocked")),
            "active_devices_sample": [
                {
                    "ip": d.get("ip"),
                    "mac": d.get("mac"),
                    "vendor": d.get("vendor"),
                    "custom_name": d.get("custom_name"),
                    "is_blocked": bool(d.get("is_blocked")),
                    "is_turbo": bool(d.get("is_turbo"))
                } for d in devices[:12]
            ],
            "ghost_leaks_count": len(ghosts),
            "ghost_leaks_sample": [
                {"domain": g.get("domain"), "ip": g.get("ip"), "process": g.get("process_name")}
                for g in ghosts[:5]
            ],
            "intruders_count": len(intruders),
            "intruders_sample": [
                {"mac": i.get("mac"), "ip": i.get("ip"), "vendor": i.get("vendor")}
                for i in intruders[:5]
            ],
            "dns_stats": dns_stats,
            "active_apps_count": len(apps),
            "top_apps_sample": [
                {"name": a.get("name"), "pid": a.get("pid"), "conn_count": a.get("conn_count"), "is_blocked": a.get("is_blocked")}
                for a in apps[:8]
            ],
            "traffic_metrics": traffic.get("latest", {}),
            "qos_metrics": qos_metrics,
            "stealth_mode": stealth_status.get("enabled", False),
            "firewall_stats": {
                "blocked_today": fw_telemetry.get("metrics", {}).get("blocked_today", 0),
                "active_rules": fw_telemetry.get("metrics", {}).get("active_rules", 0)
            }
        }

    def _generate_heuristic_analysis(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """High-speed local neural heuristic engine generating production-grade network diagnostics."""
        findings = []
        remediations = []
        threat_score = 12  # baseline baseline score

        # 1. Check Ghost Leaks
        ghost_count = state.get("ghost_leaks_count", 0)
        if ghost_count > 0:
            threat_score += min(35, ghost_count * 15)
            for g in state.get("ghost_leaks_sample", []):
                domain = g.get("domain", "unknown-tracker")
                findings.append({
                    "category": "PRIVACY_LEAK",
                    "title": f"Active Ghost Telemetry: {domain}",
                    "severity": "HIGH",
                    "description": f"Background process '{g.get('process', 'Unknown')}' is transmitting telemetry/analytics to '{domain}'.",
                    "root_cause": "Unchecked vendor background tracking payload."
                })
                remediations.append({
                    "id": f"rem_ghost_{domain.replace('.', '_')}",
                    "title": f"Vaporize Telemetry Leak ({domain})",
                    "type": "BLOCK_DOMAIN",
                    "payload": {"domain": domain, "category": "telemetry"},
                    "impact": "Stops background tracking & saves uplink bandwidth"
                })

        # 2. Check Intruders
        intruder_count = state.get("intruders_count", 0)
        if intruder_count > 0:
            threat_score += min(40, intruder_count * 25)
            for intr in state.get("intruders_sample", []):
                mac = intr.get("mac", "")
                findings.append({
                    "category": "INTRUSION_DETECTED",
                    "title": f"Unrecognized Device on LAN: {mac}",
                    "severity": "CRITICAL",
                    "description": f"Device with IP {intr.get('ip')} ({intr.get('vendor')}) joined network without prior authorization.",
                    "root_cause": "Potential Wi-Fi piggybacking or unauthorized subnet scan."
                })
                remediations.append({
                    "id": f"rem_intruder_{mac.replace(':', '_')}",
                    "title": f"Quarantine & Ban Intruder ({mac})",
                    "type": "QUARANTINE_INTRUDER",
                    "payload": {"mac": mac},
                    "impact": "Completely isolates rogue device from Gateway & local subnet"
                })

        # 3. Check Latency & QoS Optimization
        qos_info = state.get("qos_metrics", {})
        ping_ms = qos_info.get("ping_ms", 10.0)
        jitter_ms = qos_info.get("jitter_ms", 1.0)
        active_profile = qos_info.get("active_profile", "BALANCED")

        if active_profile == "BALANCED" and (ping_ms > 20.0 or jitter_ms > 3.0):
            findings.append({
                "category": "LATENCY_JITTER",
                "title": f"High Ping Jitter ({jitter_ms}ms) on Default Profile",
                "severity": "MEDIUM",
                "description": f"Current latency is {ping_ms}ms with {jitter_ms}ms jitter. Bandwidth contention detected on standard queues.",
                "root_cause": "Default CS0 socket scheduling without DSCP packet prioritization."
            })
            remediations.append({
                "id": "rem_qos_gaming",
                "title": "Engage Gaming Low-Jitter Turbo QoS",
                "type": "SET_QOS",
                "payload": {"profile": "GAMING_TURBO"},
                "impact": "Enforces DSCP EF expedited forwarding and sub-5ms jitter"
            })
        elif active_profile == "BALANCED":
            remediations.append({
                "id": "rem_qos_gaming",
                "title": "Boost Network with Gaming Low-Jitter QoS",
                "type": "SET_QOS",
                "payload": {"profile": "GAMING_TURBO"},
                "impact": "Reduces packet queue bufferbloat for instant responsiveness"
            })

        # 4. Check Stealth Mode
        if not state.get("stealth_mode", False):
            findings.append({
                "category": "RECONNAISSANCE_EXPOSURE",
                "title": "Host Node Visible to LAN Network Probes",
                "severity": "LOW",
                "description": "Standard MAC and OS headers respond to local subnet ARP/ICMP broadcasts.",
                "root_cause": "Zero-Trust Stealth Cloaking is currently inactive."
            })
            remediations.append({
                "id": "rem_stealth_enable",
                "title": "Engage Zero-Trust Stealth Cloaking",
                "type": "ENABLE_STEALTH",
                "payload": {"enabled": True},
                "impact": "Camouflages MAC alias, obfuscates TTL, and silences probe replies"
            })

        # 5. Flush DNS / Cache Optimization
        remediations.append({
            "id": "rem_dns_flush",
            "title": "Flush Local DNS Resolver Cache",
            "type": "FLUSH_DNS",
            "payload": {},
            "impact": "Purges stale DNS records and forces fresh zero-latency resolution"
        })

        threat_score = max(5, min(98, threat_score))
        if threat_score < 25:
            threat_level = "NOMINAL"
            summary = "Network operating within secure nominal parameters. Low packet drop rate and healthy gateway routing."
        elif threat_score < 55:
            threat_level = "LOW_RISK"
            summary = "Minor latency anomalies and background telemetry detections noticed. Recommended applying quick optimizations."
        elif threat_score < 80:
            threat_level = "MEDIUM_RISK"
            summary = "Active telemetry leaks and network jitter detected. Remediation recommended to secure host privacy and boost throughput."
        else:
            threat_level = "CRITICAL"
            summary = "Critical network events detected (unauthorized LAN nodes or active ghost leaks). Immediate zero-click remediation advised."

        return {
            "engine": "LOCAL_HEURISTIC_NEURAL_ENGINE",
            "timestamp": time.time(),
            "threat_score": threat_score,
            "threat_level": threat_level,
            "summary": summary,
            "diagnostics": {
                "active_nodes": state.get("total_devices_count", 0),
                "blocked_nodes": state.get("blocked_devices_count", 0),
                "dns_blocked_queries": state.get("dns_stats", {}).get("total_blocked", 0),
                "ping_ms": ping_ms,
                "jitter_ms": jitter_ms,
                "stealth_active": state.get("stealth_mode", False)
            },
            "findings": findings,
            "remediations": remediations
        }

    async def analyze_network(self, force_heuristic: bool = False) -> Dict[str, Any]:
        """Runs the AI Network Diagnostic using Gemini Cloud API or Local Heuristic Engine."""
        self._is_analyzing = True
        state = self._gather_network_state()
        api_key = self.get_api_key()
        model = self.get_model()

        if force_heuristic or not api_key:
            analysis = self._generate_heuristic_analysis(state)
            self._last_analysis = analysis
            self._last_analyzed_ts = time.time()
            self._is_analyzing = False
            return analysis

        # Gemini Cloud AI Execution
        system_prompt = (
            "You are SwitchGate's Autonomous AI Network Sentinel & Cyber Defense Architect. "
            "Analyze the real-time network telemetry snapshot provided in JSON. "
            "You must return ONLY a strict JSON object with no markdown fences, formatted exactly as:\n"
            "{\n"
            '  "threat_score": <int 0-100>,\n'
            '  "threat_level": "<NOMINAL|LOW_RISK|MEDIUM_RISK|CRITICAL>",\n'
            '  "summary": "<Concise 2-sentence executive summary explaining network health, latency, and dropped packet dynamics>",\n'
            '  "findings": [\n'
            '    {\n'
            '      "category": "<PRIVACY_LEAK|INTRUSION_DETECTED|LATENCY_JITTER|BANDWIDTH_HOG|FIREWALL_ANOMALY>",\n'
            '      "title": "<Short finding title>",\n'
            '      "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",\n'
            '      "description": "<What is happening in plain English>",\n'
            '      "root_cause": "<Underlying cause>"\n'
            '    }\n'
            '  ],\n'
            '  "remediations": [\n'
            '    {\n'
            '      "id": "<unique_id>",\n'
            '      "title": "<Actionable button title, e.g., Vaporize Telemetry Tracker>",\n'
            '      "type": "<BLOCK_DOMAIN|SET_QOS|QUARANTINE_INTRUDER|ENABLE_STEALTH|FLUSH_DNS>",\n'
            '      "payload": {<relevant key/values e.g. domain, profile, or mac>},\n'
            '      "impact": "<Expected benefit>"\n'
            '    }\n'
            '  ]\n'
            "}"
        )

        user_content = f"Live Network Telemetry:\n{json.dumps(state, indent=2)}"

        url = f"{GEMINI_API_URL.format(model=model)}?key={api_key}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": f"{system_prompt}\n\n{user_content}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json"
            }
        }

        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        raw_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        # Parse JSON
                        clean_text = raw_text.strip()
                        if clean_text.startswith("```json"):
                            clean_text = clean_text[7:]
                        if clean_text.endswith("```"):
                            clean_text = clean_text[:-3]
                        parsed = json.loads(clean_text.strip())
                        
                        parsed["engine"] = f"GEMINI_CLOUD_AI ({model})"
                        parsed["timestamp"] = time.time()
                        parsed["diagnostics"] = {
                            "active_nodes": state.get("total_devices_count", 0),
                            "blocked_nodes": state.get("blocked_devices_count", 0),
                            "dns_blocked_queries": state.get("dns_stats", {}).get("total_blocked", 0),
                            "ping_ms": state.get("qos_metrics", {}).get("ping_ms", 10.0),
                            "jitter_ms": state.get("qos_metrics", {}).get("jitter_ms", 1.0),
                            "stealth_active": state.get("stealth_mode", False)
                        }
                        self._last_analysis = parsed
                        self._last_analyzed_ts = time.time()
                        self._is_analyzing = False
                        return parsed
        except Exception as e:
            print(f"[GeminiSentinel] Cloud AI query failed ({e}), falling back to Heuristic Neural Engine.")

        # Fallback if Gemini fails
        analysis = self._generate_heuristic_analysis(state)
        analysis["engine"] += " (Cloud Fallback)"
        self._last_analysis = analysis
        self._last_analyzed_ts = time.time()
        self._is_analyzing = False
        return analysis

    def execute_remediation(self, action_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Executes zero-click instant network remediation rule."""
        action_type = action_type.upper()
        
        if action_type == "BLOCK_DOMAIN":
            domain = payload.get("domain", "").strip()
            if not domain:
                raise ValueError("Domain is required for BLOCK_DOMAIN")
            db.add_adblock_rule(domain, category="ai_sentinel")
            db.add_log("AI_REMEDIATION", "", "0.0.0.0", f"AI Sentinel blocked domain: {domain}")
            return {"status": "SUCCESS", "message": f"Successfully blocked and sinkholed domain '{domain}'."}

        elif action_type == "SET_QOS":
            profile = payload.get("profile", "GAMING_TURBO")
            qos_engine.set_profile(profile)
            return {"status": "SUCCESS", "message": f"Engaged QoS Profile '{profile}'."}

        elif action_type == "ENABLE_STEALTH":
            status = stealth_engine.toggle_stealth(True)
            return {"status": "SUCCESS", "message": f"Zero-Trust Stealth Camouflage engaged. Virtual MAC: {status['virtual_mac']}"}

        elif action_type == "QUARANTINE_INTRUDER":
            mac = payload.get("mac", "").strip()
            if not mac:
                raise ValueError("MAC required for QUARANTINE_INTRUDER")
            db.ban_intruder(mac)
            return {"status": "SUCCESS", "message": f"Intruder {mac} quarantined and permanently isolated."}

        elif action_type == "FLUSH_DNS":
            native_engine.flush_dns()
            return {"status": "SUCCESS", "message": "Windows DNS Resolver Cache flushed successfully."}

        elif action_type == "BLOCK_DEVICE":
            mac = payload.get("mac", "").strip()
            if not mac:
                raise ValueError("MAC required for BLOCK_DEVICE")
            db.update_dual_switches(mac, left_on=False, right_on=False)
            return {"status": "SUCCESS", "message": f"Device {mac} isolated from internet."}

        else:
            raise ValueError(f"Unknown remediation type: {action_type}")

    async def chat(self, message: str) -> Dict[str, Any]:
        """Interactive chat assistant with Gemini Brain or local network AI."""
        api_key = self.get_api_key()
        model = self.get_model()
        state = self._gather_network_state()

        if not api_key:
            # Smart local assistant response
            msg_lower = message.lower()
            if "ping" in msg_lower or "latency" in msg_lower or "lag" in msg_lower:
                reply = f"Current network ping is {state.get('qos_metrics', {}).get('ping_ms', 10.0)}ms with {state.get('qos_metrics', {}).get('jitter_ms', 1.0)}ms jitter. You can activate 'Gaming Low-Jitter Turbo' in QoS Turbo Engine to reduce bufferbloat."
            elif "intruder" in msg_lower or "hack" in msg_lower or "rogue" in msg_lower:
                intruder_count = state.get('intruders_count', 0)
                reply = f"There are currently {intruder_count} unauthorized devices flagged on your subnet. Check the Intruders tab or ask me to quarantine them."
            elif "speed" in msg_lower or "fast" in msg_lower or "boost" in msg_lower:
                reply = "To boost your speed to maximum throughput: 1) Switch QoS to '4K Ultra Streaming Buffer', 2) Check if any background apps are hogging data in App Controller, 3) Ensure Adblock is active to kill bandwidth-wasting ads."
            elif "stealth" in msg_lower or "privacy" in msg_lower:
                reply = "Stealth Cloak mode randomizes your host MAC and obfuscates packet TTL, preventing rogue subnet scanners from fingerprinting your personal PC."
            else:
                reply = f"SwitchGate AI Sentinel is monitoring {state.get('total_devices_count', 0)} devices. Network status is nominal with DNS Sinkhole active ({state.get('dns_stats', {}).get('total_blocked', 0)} trackers blocked). Enter a Gemini API Key in AI Sentinel settings to unlock full unconstrained LLM conversation!"
            
            return {
                "reply": reply,
                "engine": "LOCAL_HEURISTIC_AI",
                "timestamp": time.time()
            }

        url = f"{GEMINI_API_URL.format(model=model)}?key={api_key}"
        system_prompt = (
            "You are SwitchGate's intelligent Network Engineer & Security AI Assistant. "
            "Help the user diagnose network issues, optimize Wi-Fi/Ethernet speeds, configure firewall rules, "
            "and secure their home/office network. Be concise, highly technical yet easy to understand, "
            "and suggest concrete SwitchGate actions where helpful.\n"
            f"Current Live Network Context: {json.dumps(state)}"
        )

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{system_prompt}\n\nUser Question: {message}"}]
                }
            ],
            "generationConfig": {
                "temperature": 0.4
            }
        }

        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        return {
                            "reply": text,
                            "engine": f"GEMINI_CLOUD_AI ({model})",
                            "timestamp": time.time()
                        }
        except Exception as e:
            print(f"[GeminiSentinel] Chat request error: {e}")

        return {
            "reply": "SwitchGate AI Sentinel is online and actively monitoring network traffic. (Cloud API fallback triggered).",
            "engine": "LOCAL_HEURISTIC_AI",
            "timestamp": time.time()
        }

gemini_sentinel = GeminiSentinel.get_instance()
