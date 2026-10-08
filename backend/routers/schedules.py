"""
SwitchGate - Schedules & Network Automation Router v2.0
Allows configuring recurring curfew schedules, live countdown sleep timers,
and autonomous network background routines.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from backend.database import db
from backend.core.scheduler import scheduler

router = APIRouter(prefix="/api/schedules", tags=["Schedules & Automation"])


class ScheduleCreateRequest(BaseModel):
    mac: str
    name: str
    start_time: str # "22:00"
    end_time: str   # "06:00"
    days: str = "ALL" # "ALL", "WEEKDAYS", "WEEKENDS", "MON,TUE..."


class ScheduleToggleRequest(BaseModel):
    is_active: Optional[bool] = None


class TimerCreateRequest(BaseModel):
    mac: str
    minutes: int = Field(gt=0, le=1440, description="Duration in minutes (1 to 1440)")
    action: str = Field(default="BLOCK", description="Action upon expiry: 'BLOCK' or 'RESTORE'")
    name: Optional[str] = None


class RoutineUpdateRequest(BaseModel):
    auto_scan_enabled: Optional[bool] = None
    auto_scan_interval_mins: Optional[int] = None
    auto_audit_enabled: Optional[bool] = None
    auto_audit_interval_hours: Optional[int] = None
    auto_quarantine_enabled: Optional[bool] = None


class TemplateApplyRequest(BaseModel):
    mac: str
    template_key: str # "kids_bedtime", "study_focus", "night_saver"


def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────
# 1. Recurring Schedules CRUD
# ─────────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[Dict[str, Any]])
async def list_schedules():
    """Lists all recurring access window and curfew schedules with device details."""
    schedules = db.get_schedules()
    devices = {d["mac"].lower(): d for d in db.get_all_devices()}

    enriched = []
    for s in schedules:
        mac = s.get("mac", "").lower()
        dev = devices.get(mac, {})
        item = dict(s)
        item["device_name"] = dev.get("custom_name", s.get("name", mac))
        item["device_ip"] = dev.get("ip", "")
        item["device_type"] = dev.get("device_type", "unknown")
        item["is_device_blocked"] = bool(dev.get("is_blocked", 0))
        enriched.append(item)
    return enriched


@router.post("")
async def create_schedule(req: ScheduleCreateRequest):
    """Creates a new recurring curfew schedule rule."""
    clean_mac = req.mac.strip().lower().replace("-", ":")
    rule_id = db.add_schedule(
        mac=clean_mac,
        name=req.name.strip(),
        start_time=req.start_time.strip(),
        end_time=req.end_time.strip(),
        days=req.days.strip().upper()
    )
    _notify_state_change()
    return {
        "status": "success",
        "id": rule_id,
        "message": f"Schedule '{req.name}' successfully activated for {clean_mac}"
    }


@router.post("/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: int, req: Optional[ScheduleToggleRequest] = None):
    """Toggles a schedule between Active and Paused."""
    is_active = req.is_active if req else None
    success = db.toggle_schedule(schedule_id, is_active)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _notify_state_change()
    rule = db.get_schedule(schedule_id)
    return {
        "status": "success",
        "id": schedule_id,
        "is_active": bool(rule.get("is_active", 0)) if rule else False,
        "message": "Schedule active status updated"
    }


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: int):
    """Deletes a schedule rule."""
    success = db.delete_schedule(schedule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _notify_state_change()
    return {"status": "success", "id": schedule_id, "message": "Schedule rule deleted"}


# ─────────────────────────────────────────────────────────────────────────
# 2. Countdown Sleep Timers (Live Ticking Timers)
# ─────────────────────────────────────────────────────────────────────────

@router.get("/timers", response_model=List[Dict[str, Any]])
async def list_active_timers():
    """Returns all active countdown sleep timers with remaining seconds."""
    return scheduler.get_active_timers()


@router.post("/timers")
async def start_countdown_timer(req: TimerCreateRequest):
    """Starts a sleep countdown timer for a specific device."""
    clean_mac = req.mac.strip().lower().replace("-", ":")
    result = scheduler.add_countdown_timer(
        mac=clean_mac,
        duration_minutes=req.minutes,
        action=req.action,
        name=req.name or ""
    )
    _notify_state_change()
    return {
        "status": "success",
        "timer": result,
        "message": f"Timer of {req.minutes} mins started for {result.get('name', clean_mac)}"
    }


@router.delete("/timers/{mac}")
async def cancel_countdown_timer(mac: str):
    """Cancels an active countdown sleep timer."""
    clean_mac = mac.strip().lower().replace("-", ":")
    scheduler.cancel_countdown_timer(clean_mac)
    _notify_state_change()
    return {"status": "success", "mac": clean_mac, "message": "Sleep timer cancelled"}


# ─────────────────────────────────────────────────────────────────────────
# 3. Autonomous Background Routines
# ─────────────────────────────────────────────────────────────────────────

@router.get("/routines", response_model=Dict[str, Any])
async def get_routines():
    """Returns live status of all background autonomous routines."""
    return scheduler.get_routines_status()


@router.post("/routines")
async def update_routines(req: RoutineUpdateRequest):
    """Updates intervals and toggle flags for autonomous background routines."""
    if req.auto_scan_enabled is not None:
        db.set_setting("auto_scan_enabled", "1" if req.auto_scan_enabled else "0")
    if req.auto_scan_interval_mins is not None:
        db.set_setting("auto_scan_interval_mins", str(max(1, req.auto_scan_interval_mins)))

    if req.auto_audit_enabled is not None:
        db.set_setting("auto_audit_enabled", "1" if req.auto_audit_enabled else "0")
    if req.auto_audit_interval_hours is not None:
        db.set_setting("auto_audit_interval_hours", str(max(1, req.auto_audit_interval_hours)))

    if req.auto_quarantine_enabled is not None:
        db.set_setting("auto_quarantine", "1" if req.auto_quarantine_enabled else "0")

    _notify_state_change()
    return {
        "status": "success",
        "routines": scheduler.get_routines_status(),
        "message": "Autonomous routines settings updated"
    }


# ─────────────────────────────────────────────────────────────────────────
# 4. Pre-configured 1-Click Rule Templates
# ─────────────────────────────────────────────────────────────────────────

TEMPLATES = {
    "kids_bedtime": {
        "name": "🌙 Kids Bedtime Curfew",
        "start_time": "22:00",
        "end_time": "06:00",
        "days": "ALL"
    },
    "study_focus": {
        "name": "📚 Study Focus Window",
        "start_time": "14:00",
        "end_time": "17:00",
        "days": "WEEKDAYS"
    },
    "night_saver": {
        "name": "🔋 Overnight Wi-Fi Saver",
        "start_time": "01:00",
        "end_time": "06:30",
        "days": "ALL"
    }
}

@router.post("/templates/apply")
async def apply_template(req: TemplateApplyRequest):
    """Applies a pre-configured template rule to a device in 1 click."""
    clean_mac = req.mac.strip().lower().replace("-", ":")
    template = TEMPLATES.get(req.template_key)
    if not template:
        raise HTTPException(status_code=400, detail="Unknown template key")

    dev = db.get_device(clean_mac)
    dev_name = dev.get("custom_name", clean_mac) if dev else clean_mac
    rule_name = f"{template['name']} ({dev_name})"

    rule_id = db.add_schedule(
        mac=clean_mac,
        name=rule_name,
        start_time=template["start_time"],
        end_time=template["end_time"],
        days=template["days"]
    )
    _notify_state_change()
    return {
        "status": "success",
        "id": rule_id,
        "message": f"Template '{template['name']}' applied to {dev_name}"
    }
