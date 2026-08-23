"""
SwitchGate - Real-Time App Network REST API Router
Enables monitoring and ON/OFF switching of real running Windows applications.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.core.app_controller import app_controller

router = APIRouter(prefix="/api/apps", tags=["Apps Network Controller"])

class AppToggleRequest(BaseModel):
    action: str # "ON" or "OFF"
    exe_path: str = ""

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("", response_model=List[Dict[str, Any]])
async def get_active_apps():
    """Returns 100% genuine active Windows processes using network connections."""
    return app_controller.get_real_active_apps()

@router.post("/{app_name}/toggle")
async def toggle_app_switch(app_name: str, req: AppToggleRequest):
    """Flips an App's Internet Access ON/OFF without killing the process."""
    app_clean = app_name.strip()
    success = app_controller.toggle_app_internet(app_clean, req.exe_path.strip(), req.action)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle firewall rule for app")
    
    _notify_state_change()
    
    return {
        "status": "success",
        "app_name": app_clean,
        "action": req.action.upper(),
        "is_blocked": req.action.upper() == "OFF",
        "message": f"{app_clean} internet switched {req.action.upper()} safely."
    }

