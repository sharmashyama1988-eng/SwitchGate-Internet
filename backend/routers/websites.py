"""
SwitchGate - Live Websites & Domain Controller REST API Router (PAC Enabled)
"""
import asyncio
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.core.url_controller import url_controller

router = APIRouter(prefix="/api/websites", tags=["Websites Controller"])

class WebsiteToggleRequest(BaseModel):
    action: str # "ON" or "OFF"

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("/switchgate.pac")
async def get_pac_script():
    """Serves dynamic Proxy Auto-Configuration (PAC) script to Windows browsers."""
    pac_content = url_controller.generate_pac_script()
    return Response(content=pac_content, media_type="application/x-ns-proxy-autoconfig")

@router.get("", response_model=List[Dict[str, Any]])
async def get_live_websites():
    """Returns list of live websites/domains accessed on the system."""
    return url_controller.get_live_websites()

@router.post("/{domain}/toggle")
async def toggle_website_switch(domain: str, req: WebsiteToggleRequest):
    """Switches access to a website ON or OFF across all browsers."""
    clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
    success = url_controller.toggle_website(clean_domain, req.action)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle website rule")
    
    _notify_state_change()
    
    return {
        "status": "success",
        "domain": clean_domain,
        "action": req.action.upper(),
        "is_blocked": req.action.upper() == "OFF",
        "message": f"Website {clean_domain} switched {req.action.upper()} across all browsers."
    }

