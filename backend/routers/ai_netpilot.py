"""
SwitchGate - AI Netpilot Router v3.0
REST API endpoints for Netpilot Engine controls, telemetry, and deep-level optimization.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.core.ai_netpilot import ai_netpilot

router = APIRouter(prefix="/api/netpilot", tags=["AI Netpilot"])


class ToggleFeatureRequest(BaseModel):
    feature: str
    enable: Optional[bool] = None


class ToggleMasterRequest(BaseModel):
    enable: Optional[bool] = None


@router.get("/status")
async def get_netpilot_status():
    """Returns real-time Netpilot status, metrics, adapter stats, and active technology states."""
    try:
        return ai_netpilot.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/toggle_master")
async def toggle_netpilot_master(req: ToggleMasterRequest = ToggleMasterRequest()):
    """Toggles or sets the master Netpilot engine state."""
    try:
        new_state = ai_netpilot.toggle_master(req.enable)
        return {
            "success": True,
            "master_enabled": new_state,
            "status": ai_netpilot.get_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/toggle_feature")
async def toggle_netpilot_feature(req: ToggleFeatureRequest):
    """Toggles or sets an individual Netpilot technology: rf_antenna, network_switcher, network_booster, super_wifi."""
    valid_features = ["rf_antenna", "network_switcher", "network_booster", "super_wifi"]
    if req.feature not in valid_features:
        raise HTTPException(status_code=400, detail=f"Invalid feature '{req.feature}'. Must be one of {valid_features}")

    try:
        new_state = ai_netpilot.toggle_feature(req.feature, req.enable)
        return {
            "success": True,
            "feature": req.feature,
            "enabled": new_state,
            "status": ai_netpilot.get_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize_now")
async def optimize_netpilot_now():
    """Executes a full deep-level network optimization sweep across adapters and Windows TCP/IP stack."""
    try:
        res = ai_netpilot.optimize_now()
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
