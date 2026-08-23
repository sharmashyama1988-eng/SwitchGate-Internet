"""
SwitchGate - Enterprise Advanced Settings & System Control Router
Implements the full 5-category advanced settings matrix:
1. Core Network & Interface Control
2. Advanced Traffic & App Filtering
3. Security, Anti-Virus & Smart Filtering
4. Connection Security & Privacy
5. System Auditing, Logs & Self-Protection
"""
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, Optional

from backend.database import db
from backend.core.system_integration import system_integration
from backend.config import AppConfig

router = APIRouter(prefix="/api/settings", tags=["Settings"])


class AdvancedSettingsPayload(BaseModel):
    # Core system toggles
    run_on_startup: Optional[bool] = None
    minimize_to_tray: Optional[bool] = None
    auto_quarantine: Optional[bool] = None

    # 1. Core Network & Interface Control
    adapter_binding: Optional[str] = None
    auto_profile_switching: Optional[bool] = None
    failsafe_mode: Optional[str] = None  # "ALLOW" or "DROP"
    dpi_depth: Optional[str] = None  # "Lite", "Standard", "Deep"

    # 2. Advanced Traffic & App Filtering
    process_blocking_enabled: Optional[bool] = None
    protocol_hardening: Optional[bool] = None
    stealth_mode: Optional[bool] = None
    bandwidth_throttling: Optional[bool] = None

    # 3. Security, Anti-Virus & Smart Filtering
    realtime_payload_hashing: Optional[bool] = None
    adblock_aggression: Optional[str] = None  # "Low", "Medium", "High"
    dns_safesearch: Optional[bool] = None
    threat_intel_auto_update: Optional[bool] = None

    # 4. Connection Security & Privacy
    enforce_ipsec: Optional[bool] = None
    secure_dns_doh: Optional[str] = None  # "Cloudflare (1.1.1.1)", "Quad9 (9.9.9.9)", "Google (8.8.8.8)", "Off"
    vpn_passthrough: Optional[bool] = None

    # 5. System Auditing, Logs & Self-Protection
    audit_logging_level: Optional[str] = None  # "DROPS_ONLY", "ALL_CONNECTIONS", "THREATS_ONLY"
    log_retention_days: Optional[int] = None  # 7, 14, 30, 90
    anti_tamper_protection: Optional[bool] = None
    live_attack_alerting: Optional[bool] = None


def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass


@router.get("")
async def get_all_settings() -> Dict[str, Any]:
    """Retrieves all 5 categories of settings with live defaults."""
    startup_enabled = system_integration.get_startup_status()

    return {
        # Core
        "run_on_startup": startup_enabled,
        "minimize_to_tray": db.get_setting("minimize_to_tray", "1") == "1",
        "auto_quarantine": db.get_setting("auto_quarantine", "0") == "1",
        "emergency_pause_active": db.get_setting("emergency_pause_active", "0") == "1",
        "turbo_focus_mac": db.get_setting("turbo_focus_mac", ""),

        # 1. Core Network & Interface Control
        "adapter_binding": db.get_setting("adapter_binding", AppConfig.INTERFACE_NAME or "All Network Adapters"),
        "auto_profile_switching": db.get_setting("auto_profile_switching", "1") == "1",
        "failsafe_mode": db.get_setting("failsafe_mode", "DROP"),
        "dpi_depth": db.get_setting("dpi_depth", "Deep"),

        # 2. Advanced Traffic & App Filtering
        "process_blocking_enabled": db.get_setting("process_blocking_enabled", "1") == "1",
        "protocol_hardening": db.get_setting("protocol_hardening", "1") == "1",
        "stealth_mode": db.get_setting("stealth_mode", "1") == "1",
        "bandwidth_throttling": db.get_setting("bandwidth_throttling", "0") == "1",

        # 3. Security, Anti-Virus & Smart Filtering
        "realtime_payload_hashing": db.get_setting("realtime_payload_hashing", "1") == "1",
        "adblock_aggression": db.get_setting("adblock_aggression", "High"),
        "dns_safesearch": db.get_setting("dns_safesearch", "1") == "1",
        "threat_intel_auto_update": db.get_setting("threat_intel_auto_update", "1") == "1",

        # 4. Connection Security & Privacy
        "enforce_ipsec": db.get_setting("enforce_ipsec", "0") == "1",
        "secure_dns_doh": db.get_setting("secure_dns_doh", "Cloudflare (1.1.1.1)"),
        "vpn_passthrough": db.get_setting("vpn_passthrough", "1") == "1",

        # 5. System Auditing, Logs & Self-Protection
        "audit_logging_level": db.get_setting("audit_logging_level", "THREATS_ONLY"),
        "log_retention_days": int(db.get_setting("log_retention_days", "14")),
        "anti_tamper_protection": db.get_setting("anti_tamper_protection", "1") == "1",
        "live_attack_alerting": db.get_setting("live_attack_alerting", "1") == "1",

        # Hardware Network Context
        "gateway_ip": AppConfig.GATEWAY_IP,
        "local_ip": AppConfig.LOCAL_IP,
        "interface": AppConfig.INTERFACE_NAME or "Wi-Fi Adapter",
        "dns_port": AppConfig.DNS_PORT
    }


@router.post("")
async def update_settings(req: AdvancedSettingsPayload):
    """Updates settings and instantly propagates changes to active background engines."""
    # 1. System & Windows Startup
    if req.run_on_startup is not None:
        system_integration.set_run_on_startup(req.run_on_startup)
    if req.minimize_to_tray is not None:
        db.set_setting("minimize_to_tray", "1" if req.minimize_to_tray else "0")
    if req.auto_quarantine is not None:
        db.set_setting("auto_quarantine", "1" if req.auto_quarantine else "0")

    # 1. Core Network & Interface Control
    if req.adapter_binding is not None:
        db.set_setting("adapter_binding", req.adapter_binding)
    if req.auto_profile_switching is not None:
        db.set_setting("auto_profile_switching", "1" if req.auto_profile_switching else "0")
    if req.failsafe_mode is not None:
        db.set_setting("failsafe_mode", req.failsafe_mode)
    if req.dpi_depth is not None:
        db.set_setting("dpi_depth", req.dpi_depth)

    # 2. Advanced Traffic & App Filtering
    if req.process_blocking_enabled is not None:
        db.set_setting("process_blocking_enabled", "1" if req.process_blocking_enabled else "0")
    if req.protocol_hardening is not None:
        db.set_setting("protocol_hardening", "1" if req.protocol_hardening else "0")
    if req.stealth_mode is not None:
        db.set_setting("stealth_mode", "1" if req.stealth_mode else "0")
    if req.bandwidth_throttling is not None:
        db.set_setting("bandwidth_throttling", "1" if req.bandwidth_throttling else "0")

    # 3. Security, Anti-Virus & Smart Filtering
    if req.realtime_payload_hashing is not None:
        db.set_setting("realtime_payload_hashing", "1" if req.realtime_payload_hashing else "0")
    if req.adblock_aggression is not None:
        db.set_setting("adblock_aggression", req.adblock_aggression)
    if req.dns_safesearch is not None:
        db.set_setting("dns_safesearch", "1" if req.dns_safesearch else "0")
    if req.threat_intel_auto_update is not None:
        db.set_setting("threat_intel_auto_update", "1" if req.threat_intel_auto_update else "0")

    # 4. Connection Security & Privacy
    if req.enforce_ipsec is not None:
        db.set_setting("enforce_ipsec", "1" if req.enforce_ipsec else "0")
    if req.secure_dns_doh is not None:
        db.set_setting("secure_dns_doh", req.secure_dns_doh)
    if req.vpn_passthrough is not None:
        db.set_setting("vpn_passthrough", "1" if req.vpn_passthrough else "0")

    # 5. System Auditing, Logs & Self-Protection
    if req.audit_logging_level is not None:
        db.set_setting("audit_logging_level", req.audit_logging_level)
    if req.log_retention_days is not None:
        db.set_setting("log_retention_days", str(req.log_retention_days))
    if req.anti_tamper_protection is not None:
        db.set_setting("anti_tamper_protection", "1" if req.anti_tamper_protection else "0")
    if req.live_attack_alerting is not None:
        db.set_setting("live_attack_alerting", "1" if req.live_attack_alerting else "0")

    # Flush DNS and broadcast
    try:
        from backend.native.network_engine import native_engine
        native_engine.flush_dns()
    except Exception:
        pass

    _notify_state_change()

    return {"status": "success", "message": "All Advanced Settings successfully applied and synchronized."}

