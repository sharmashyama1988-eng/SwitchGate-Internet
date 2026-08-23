"""
SwitchGate Next-Gen Firewall - REST API Router
Exposes high-speed endpoints for firewall status, rules CRUD, profile switching, live audit logs, and antivirus payload scanning.
"""
import asyncio
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query

from firewall.rules_engine import rules_engine
from firewall.antivirus import antivirus
from firewall.packet_filter import packet_filter
from firewall.firewall_logger import firewall_logger
from firewall.firewall_controller import firewall_controller

router = APIRouter(prefix="/api/firewall", tags=["Next-Gen Firewall"])

# --- Request / Response Models ---
class ProfileSwitchRequest(BaseModel):
    profile: str = Field(..., description="Target security profile name: 'Public', 'Private', or 'Domain'")

class CustomRuleRequest(BaseModel):
    name: str = Field(..., description="Descriptive name of the firewall rule")
    type: str = Field(..., description="Rule match type: 'PORT', 'IP', or 'PROTOCOL'")
    direction: str = Field(default="INBOUND", description="'INBOUND', 'OUTBOUND', or 'BOTH'")
    target: str = Field(..., description="Target port (e.g. '445', '8000-8080'), IP address ('192.168.1.50'), or protocol ('ICMP')")
    action: str = Field(default="DROP", description="Action to take: 'DROP' or 'ALLOW'")
    enabled: bool = Field(default=True, description="Whether rule is immediately active")

class CustomRuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    direction: Optional[str] = None
    target: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None

class PayloadScanRequest(BaseModel):
    payload: str = Field(..., description="String, hex, or base64 payload to scan with Antivirus & Heuristic scanner")
    src_ip: Optional[str] = Field(default="127.0.0.1", description="Source IP for contextual evaluation")
    dst_port: Optional[int] = Field(default=80, description="Destination port")

class PacketInspectRequest(BaseModel):
    src_ip: str = Field(default="192.168.1.100", description="Source IP address")
    dst_ip: str = Field(default="10.0.0.1", description="Destination IP address")
    src_port: int = Field(default=49152, description="Source port")
    dst_port: int = Field(default=445, description="Destination port")
    protocol: str = Field(default="TCP", description="Transport protocol: 'TCP', 'UDP', 'ICMP'")
    direction: str = Field(default="INBOUND", description="'INBOUND' or 'OUTBOUND'")
    payload: Optional[str] = Field(default=None, description="Optional packet payload string")


def _broadcast_firewall_change():
    """Notifies connected WebSocket clients of state changes if WebSocketHub is active."""
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass


# --- Endpoints ---

@router.get("/status")
async def get_firewall_status():
    """Returns complete real-time status of the Next-Generation Firewall subsystem."""
    return firewall_controller.get_status()


@router.post("/toggle")
async def toggle_firewall():
    """Toggles master Next-Gen Firewall state (Enabled / Disabled)."""
    new_state = rules_engine.toggle_enabled()
    _broadcast_firewall_change()
    return {
        "status": "success",
        "enabled": new_state,
        "message": f"SwitchGate Firewall is now {'ACTIVE' if new_state else 'DISABLED'}."
    }


@router.get("/profile")
async def get_current_profile():
    """Returns the currently active network profile and definitions for all profiles."""
    return {
        "current_profile": rules_engine.get_current_profile(),
        "profiles": rules_engine.get_profiles(),
        "active_config": rules_engine.get_current_profile_data()
    }


@router.post("/profile")
async def set_firewall_profile(req: ProfileSwitchRequest):
    """Switches the active security profile (Public, Private, or Domain)."""
    success = rules_engine.set_profile(req.profile)
    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid profile name '{req.profile}'. Valid choices are: {list(rules_engine.get_profiles().keys())}"
        )
    # Optionally trigger netsh sync
    firewall_controller.sync_netsh_firewall()
    _broadcast_firewall_change()
    return {
        "status": "success",
        "current_profile": req.profile,
        "message": f"Network security profile successfully switched to '{req.profile}'."
    }


@router.get("/rules")
async def get_firewall_rules():
    """Returns all custom rules, current profile ACLs, and global firewall settings."""
    return {
        "enabled": rules_engine.is_enabled(),
        "current_profile": rules_engine.get_current_profile(),
        "custom_rules": rules_engine.get_custom_rules(),
        "profiles": rules_engine.get_profiles(),
        "settings": rules_engine.get_settings()
    }


@router.post("/rules")
async def add_firewall_rule(req: CustomRuleRequest):
    """Creates and activates a new custom firewall rule."""
    rule = rules_engine.add_custom_rule(
        name=req.name,
        rule_type=req.type,
        direction=req.direction,
        target=req.target,
        action=req.action,
        enabled=req.enabled
    )
    _broadcast_firewall_change()
    return {
        "status": "success",
        "rule": rule,
        "message": f"Firewall rule '{req.name}' successfully added."
    }


@router.put("/rules/{rule_id}")
async def update_firewall_rule(rule_id: str, req: CustomRuleUpdateRequest):
    """Updates an existing custom rule."""
    updates = {k: v for k, v in req.dict().items() if v is not None}
    updated_rule = rules_engine.update_custom_rule(rule_id, **updates)
    if not updated_rule:
        raise HTTPException(status_code=404, detail=f"Rule with ID '{rule_id}' not found.")
    _broadcast_firewall_change()
    return {
        "status": "success",
        "rule": updated_rule,
        "message": f"Firewall rule '{rule_id}' updated."
    }


@router.delete("/rules/{rule_id}")
async def delete_firewall_rule(rule_id: str):
    """Deletes a custom firewall rule."""
    deleted = rules_engine.delete_custom_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule with ID '{rule_id}' not found.")
    _broadcast_firewall_change()
    return {
        "status": "success",
        "rule_id": rule_id,
        "message": f"Firewall rule '{rule_id}' deleted."
    }


@router.post("/rules/{rule_id}/toggle")
async def toggle_firewall_rule(rule_id: str):
    """Toggles a specific rule between enabled and disabled."""
    new_state = rules_engine.toggle_custom_rule(rule_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID '{rule_id}' not found.")
    _broadcast_firewall_change()
    return {
        "status": "success",
        "rule_id": rule_id,
        "enabled": new_state,
        "message": f"Rule '{rule_id}' is now {'ENABLED' if new_state else 'DISABLED'}."
    }


@router.get("/logs")
async def get_firewall_logs(
    limit: int = Query(default=50, ge=1, le=1000),
    severity: Optional[str] = Query(default=None),
    verdict: Optional[str] = Query(default=None)
):
    """Retrieves real-time audit logs and dropped threat events from high-speed ring buffer."""
    logs = firewall_logger.get_recent_logs(limit=limit, severity=severity, verdict=verdict)
    summary = firewall_logger.get_threat_summary()
    return {
        "logs": logs,
        "total_returned": len(logs),
        "threat_summary": summary
    }


@router.delete("/logs")
async def clear_firewall_logs():
    """Clears all audit logs from RAM ring buffer and database."""
    firewall_logger.clear_logs()
    return {"status": "success", "message": "Firewall audit logs cleared."}


@router.post("/scan-payload")
async def scan_payload_endpoint(req: PayloadScanRequest):
    """
    Real-time Antivirus & Heuristic exploit scan endpoint.
    Tests a payload string or hex against MD5 signatures and heuristic pattern rules.
    """
    result = antivirus.scan_payload(req.payload, src_ip=req.src_ip, dst_port=req.dst_port)
    return {
        "status": "success",
        "scan_result": result
    }


@router.post("/inspect-packet")
async def inspect_packet_endpoint(req: PacketInspectRequest):
    """
    Deep Packet Inspection (DPI) test endpoint.
    Evaluates an arbitrary packet tuple against the live rules engine, security profile, and antivirus.
    """
    verdict = packet_filter.inspect_packet(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        src_port=req.src_port,
        dst_port=req.dst_port,
        protocol=req.protocol,
        direction=req.direction,
        payload=req.payload,
        log_decision=True
    )
    return {
        "status": "success",
        "decision": verdict
    }


@router.get("/threats")
async def get_threat_intelligence():
    """Returns aggregated threat counts, top blocked ports, and malicious IPs."""
    return firewall_logger.get_threat_summary()


@router.post("/sync-netsh")
async def sync_netsh_endpoint():
    """Forces synchronization between SwitchGate and Windows Netsh Firewall."""
    return firewall_controller.sync_netsh_firewall()
