"""
SwitchGate - Network & Diagnostics REST API Router
Provides Gateway configuration, manual network scan triggers, live bandwidth statistics and activity logs.
"""
from fastapi import APIRouter, BackgroundTasks
from typing import Dict, Any

from backend.config import AppConfig
from backend.database import db
from backend.core.scanner import scanner
from backend.core.traffic_monitor import traffic_monitor

router = APIRouter(prefix="/api/network", tags=["Network"])

@router.get("/info")
async def get_network_info() -> Dict[str, Any]:
    devices = db.get_all_devices()
    online_count = sum(1 for d in devices if d.get("status") == "ONLINE")
    blocked_count = sum(1 for d in devices if d.get("is_blocked") == 1)

    return {
        "app_name": AppConfig.APP_NAME,
        "app_version": AppConfig.APP_VERSION,
        "local_ip": AppConfig.LOCAL_IP,
        "gateway_ip": AppConfig.GATEWAY_IP,
        "network_cidr": AppConfig.NETWORK_CIDR,
        "interface": AppConfig.INTERFACE_NAME or "Default Adapter",
        "host_mac": AppConfig.HOST_MAC,
        "is_scanning": scanner.is_scanning,
        "total_devices": len(devices),
        "online_devices": online_count,
        "blocked_devices": blocked_count,
        "block_method": AppConfig.BLOCK_METHOD
    }

@router.post("/scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """Triggers an active network scan in background."""
    if not scanner.is_scanning:
        background_tasks.add_task(scanner.scan_network)
    return {"status": "scanning", "message": "Network discovery scan initiated"}

@router.get("/metrics")
async def get_traffic_metrics():
    return traffic_monitor.get_metrics()

@router.get("/logs")
async def get_activity_logs(limit: int = 40):
    return db.get_recent_logs(limit=limit)
