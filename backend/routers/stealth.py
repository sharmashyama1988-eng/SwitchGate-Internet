"""
SwitchGate - Zero-Trust Stealth Cloaking API Router
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from backend.core.stealth_engine import stealth_engine

router = APIRouter(prefix="/api/stealth", tags=["Stealth Cloaking"])

class StealthToggleRequest(BaseModel):
    enabled: Optional[bool] = None

@router.get("/status")
async def get_stealth_status():
    return stealth_engine.get_status()

@router.post("/toggle")
async def toggle_stealth_mode(req: StealthToggleRequest = StealthToggleRequest()):
    return stealth_engine.toggle_stealth(req.enabled)
