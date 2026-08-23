"""
SwitchGate - Brave-Grade Adblock-Rust REST API Router
"""
import asyncio
from fastapi import APIRouter, Response
from backend.adblock.adblock_engine import adblock_engine

router = APIRouter(prefix="/api/adblock", tags=["Adblock Engine"])

def _notify_state_change():
    try:
        from backend.main import ws_hub
        asyncio.create_task(ws_hub.broadcast_current_state())
    except Exception:
        pass

@router.get("/stats")
async def get_adblock_stats():
    """Returns live Brave Shields adblock metrics."""
    return adblock_engine.get_stats()

@router.post("/toggle")
async def toggle_adblock():
    """Toggles Brave-Grade adblocking ON or OFF."""
    new_state = adblock_engine.toggle()
    _notify_state_change()
    return {
        "status": "success",
        "enabled": new_state,
        "message": f"Brave Shields Adblock-Rust Engine switched {'ON' if new_state else 'OFF'}."
    }

@router.get("/cosmetic.css")
async def get_cosmetic_stylesheet():
    """Serves browser element-hiding CSS stylesheet."""
    css = adblock_engine.get_cosmetic_stylesheet()
    return Response(content=css, media_type="text/css")

