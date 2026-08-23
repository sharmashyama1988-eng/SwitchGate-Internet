"""
SwitchGate - Ghost Data & Stealth Leaks REST API Router
"""
import asyncio
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any

from backend.database import db
from backend.core.ghost_detector import ghost_detector

router = APIRouter(prefix="/api/ghost-leaks", tags=["Ghost Leaks"])

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("", response_model=List[Dict[str, Any]])
async def get_active_ghost_leaks():
    return ghost_detector.get_active_leaks()

@router.post("/{leak_id}/kill")
async def kill_ghost_leak(leak_id: int):
    success = ghost_detector.kill_leak(leak_id)
    if not success:
        raise HTTPException(status_code=404, detail="Ghost leak not found")
    _notify_state_change()
    return {"status": "success", "leak_id": leak_id, "message": "Ghost leak vaporized"}

