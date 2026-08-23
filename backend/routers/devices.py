"""
SwitchGate - Devices REST API Router (Dual-Switch & Advanced Controls)
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from backend.database import db
from backend.core.blocker import blocker
from backend.core.traffic_monitor import traffic_monitor

router = APIRouter(prefix="/api/devices", tags=["Devices"])

class DualSwitchRequest(BaseModel):
    left_on: Optional[bool] = None
    right_on: Optional[bool] = None

class RenameRequest(BaseModel):
    custom_name: str
    device_type: Optional[str] = None

class EmergencyPauseRequest(BaseModel):
    active: bool

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("", response_model=List[Dict[str, Any]])
async def list_devices():
    devices = db.get_all_devices()
    metrics = traffic_monitor.get_metrics()
    device_speeds = metrics.get("device_speeds", {})

    for dev in devices:
        mac = dev.get("mac", "")
        dev["current_kbps"] = device_speeds.get(mac, 0.0)
        dev["is_blocked"] = bool(dev.get("is_blocked", 0))
        dev["adblock_enabled"] = bool(dev.get("adblock_enabled", 1))
        dev["is_turbo"] = bool(dev.get("is_turbo", 0))
        dev["left_switch_on"] = bool(dev.get("left_switch_on", 1))
        dev["right_switch_on"] = bool(dev.get("right_switch_on", 1))

    return devices

@router.post("/{mac}/switch")
async def toggle_device_switches(mac: str, req: DualSwitchRequest):
    """Handles independent Left (Internet Access) and Right (Turbo / Shield / Priority) switches."""
    mac = mac.lower().replace("-", ":")
    dev = db.get_device(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    updated_dev = db.update_dual_switches(mac, left_on=req.left_on, right_on=req.right_on)
    
    # Enforce network cut off or restore based on left switch
    if req.left_on is not None:
        if req.left_on is False:
            blocker.block_device(mac, dev["ip"])
        else:
            if not dev.get("is_banned") and db.get_setting("emergency_pause_active") != "1":
                blocker.unblock_device(mac, dev["ip"])

    # If right switch (Turbo / Priority) is toggled
    if req.right_on is not None:
        if req.right_on:
            db.set_turbo_focus(mac)
        else:
            if dev.get("is_turbo"):
                db.set_turbo_focus(None)

    _notify_state_change()

    return {
        "status": "success",
        "mac": mac,
        "left_switch_on": bool(updated_dev.get("left_switch_on")),
        "right_switch_on": bool(updated_dev.get("right_switch_on")),
        "is_blocked": bool(updated_dev.get("is_blocked")),
        "status_label": updated_dev.get("status_label")
    }

@router.post("/{mac}/turbo")
async def toggle_turbo_focus(mac: str):
    """Toggles Turbo Focus on a specific device."""
    mac = mac.lower().replace("-", ":")
    dev = db.get_device(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    is_currently_turbo = bool(dev.get("is_turbo", 0))
    target = None if is_currently_turbo else mac
    db.set_turbo_focus(target)
    
    _notify_state_change()
    return {"status": "success", "turbo_mac": target, "active": not is_currently_turbo}

@router.post("/emergency-pause")
async def toggle_emergency_pause(req: EmergencyPauseRequest):
    """Emergency Pause / Dinner Time Freeze: Cuts off or restores all home Wi-Fi."""
    count = db.set_emergency_pause(req.active)
    if req.active:
        blocker.block_all()
    else:
        blocker.unblock_all()
        
    _notify_state_change()
    return {
        "status": "success",
        "emergency_pause_active": req.active,
        "affected_devices": count,
        "message": "Whole-home Wi-Fi Paused (Dinner Time Mode)" if req.active else "Whole-home Wi-Fi Restored"
    }

@router.put("/{mac}/rename")
async def rename_device(mac: str, req: RenameRequest):
    mac = mac.lower().replace("-", ":")
    success = db.update_device_name(mac, req.custom_name.strip(), req.device_type)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    _notify_state_change()
    return {"status": "success", "mac": mac, "new_name": req.custom_name}

