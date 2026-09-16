"""
SwitchGate - AI Speed Booster & QoS Turbo Engine API Router
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.core.qos_engine import qos_engine

router = APIRouter(prefix="/api/qos", tags=["QoS Turbo Engine"])

class ProfileActivateRequest(BaseModel):
    profile_id: str

@router.get("/profiles")
async def get_profiles():
    return qos_engine.get_profiles()

@router.get("/metrics")
async def get_qos_metrics():
    return qos_engine.get_metrics()

@router.post("/activate")
async def activate_profile(req: ProfileActivateRequest):
    try:
        updated = qos_engine.set_profile(req.profile_id)
        return {"status": "SUCCESS", "active_profile": updated}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
