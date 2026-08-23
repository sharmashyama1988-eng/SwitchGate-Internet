"""
SwitchGate - Schedules & Bedtime Cutoff Router
Allows setting automatic internet cutoff schedules and countdown sleep timers per device.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List

from backend.database import db

router = APIRouter(prefix="/api/schedules", tags=["Schedules"])

class ScheduleCreateRequest(BaseModel):
    mac: str
    name: str
    start_time: str # "22:00"
    end_time: str   # "06:00"
    days: str = "ALL"

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("", response_model=List[Dict[str, Any]])
async def list_schedules():
    return db.get_schedules()

@router.post("")
async def create_schedule(req: ScheduleCreateRequest):
    clean_mac = req.mac.strip().lower().replace("-", ":")
    rule_id = db.add_schedule(
        mac=clean_mac,
        name=req.name.strip(),
        start_time=req.start_time.strip(),
        end_time=req.end_time.strip(),
        days=req.days.strip()
    )
    _notify_state_change()
    return {"status": "success", "id": rule_id, "message": f"Schedule '{req.name}' created"}

@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: int):
    success = db.delete_schedule(schedule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _notify_state_change()
    return {"status": "success", "id": schedule_id, "message": "Schedule deleted"}

