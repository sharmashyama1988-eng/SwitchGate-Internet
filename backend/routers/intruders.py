"""
SwitchGate - Intruder Alerts & Quarantine REST API Router
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.database import db
from backend.core.intruder_detector import intruder_detector

router = APIRouter(prefix="/api/intruders", tags=["Intruders"])

class TrustRequest(BaseModel):
    friendly_name: str

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("", response_model=List[Dict[str, Any]])
async def get_pending_intruders():
    return db.get_pending_intruders()

@router.post("/{mac}/ban")
async def ban_intruder(mac: str):
    clean_mac = mac.strip().lower().replace("-", ":")
    success = intruder_detector.ban_device(clean_mac)
    _notify_state_change()
    return {"status": "success", "mac": clean_mac, "banned": success}

@router.post("/{mac}/trust")
async def trust_intruder(mac: str, req: TrustRequest):
    clean_mac = mac.strip().lower().replace("-", ":")
    success = intruder_detector.trust_device(clean_mac, req.friendly_name.strip())
    _notify_state_change()
    return {"status": "success", "mac": clean_mac, "trusted": success}

