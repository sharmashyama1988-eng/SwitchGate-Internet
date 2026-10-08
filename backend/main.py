"""
SwitchGate - Master FastAPI Server & Real-Time WebSocket Hub v2.0 (kPerf Powered)
Hardened WebSocket Synchronization, Asynchronous State Snapshotting & Sub-Millisecond Event Loop
"""
import sys
import asyncio
import json
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Set, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse

from backend.config import AppConfig, BASE_DIR, BUNDLE_DIR
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine
from backend.core.scanner import scanner
from backend.core.blocker import blocker
from backend.core.dns_sinkhole import dns_sinkhole
from backend.core.traffic_monitor import traffic_monitor
from backend.core.scheduler import scheduler
from backend.core.ghost_detector import ghost_detector
from backend.core.app_controller import app_controller
from backend.core.url_controller import url_controller

from backend.routers.devices import router as devices_router
from backend.routers.network import router as network_router
from backend.routers.adblock import router as adblock_router
from backend.routers.schedules import router as schedules_router
from backend.routers.intruders import router as intruders_router
from backend.routers.ghost_leaks import router as ghost_leaks_router
from backend.routers.settings import router as settings_router
from backend.routers.apps import router as apps_router
from backend.routers.websites import router as websites_router
from backend.routers.kperf import router as kperf_router
from backend.routers.speedtest import router as speedtest_router
from backend.routers.gemini_sentinel import router as gemini_sentinel_router
from backend.routers.qos import router as qos_router
from backend.routers.stealth import router as stealth_router
from backend.routers.ai_netpilot import router as ai_netpilot_router
from backend.routers.workspace import router as workspace_router
from backend.core.gemini_sentinel import gemini_sentinel
from backend.core.qos_engine import qos_engine
from backend.core.stealth_engine import stealth_engine
from backend.core.ai_netpilot import ai_netpilot



def get_telemetry_snapshot_sync() -> Dict[str, Any]:
    """Compiles the complete 100% genuine system telemetry snapshot with full error isolation."""
    try:
        devices = db.get_all_devices()
    except Exception:
        devices = []

    try:
        metrics = traffic_monitor.get_metrics()
        device_speeds = metrics.get("device_speeds", {})
        latest_metrics = metrics.get("latest", {"download_mbps": 0.0, "upload_mbps": 0.0, "blocked_kbps": 0.0})
    except Exception:
        device_speeds = {}
        latest_metrics = {"download_mbps": 0.0, "upload_mbps": 0.0, "blocked_kbps": 0.0}

    for dev in devices:
        mac = dev.get("mac", "")
        dev["current_kbps"] = device_speeds.get(mac, 0.0)
        dev["is_blocked"] = bool(dev.get("is_blocked", 0))
        dev["adblock_enabled"] = bool(dev.get("adblock_enabled", 1))
        dev["is_turbo"] = bool(dev.get("is_turbo", 0))
        dev["left_switch_on"] = bool(dev.get("left_switch_on", 1))
        dev["right_switch_on"] = bool(dev.get("right_switch_on", 1))

    try:
        ad_stats = dns_sinkhole.get_stats()
    except Exception:
        ad_stats = {"total_blocked": 0, "total_queries": 0}

    try:
        intruders = db.get_pending_intruders()
    except Exception:
        intruders = []

    try:
        ghosts = db.get_ghost_leaks()
    except Exception:
        ghosts = []

    try:
        emergency_pause = db.get_setting("emergency_pause_active", "0") == "1"
    except Exception:
        emergency_pause = False

    try:
        real_apps = app_controller.get_real_active_apps()
    except Exception:
        real_apps = []

    try:
        real_sites = url_controller.get_live_websites()
    except Exception:
        real_sites = []

    try:
        kperf_metrics = kperf_engine.get_metrics()
    except Exception:
        kperf_metrics = {}

    try:
        from firewall.firewall_controller import firewall_controller
        fw_metrics = firewall_controller.get_telemetry()
    except Exception:
        fw_metrics = {}

    try:
        qos_data = qos_engine.get_metrics()
    except Exception:
        qos_data = {}

    try:
        stealth_data = stealth_engine.get_status()
    except Exception:
        stealth_data = {}

    try:
        sentinel_data = gemini_sentinel.get_status()
    except Exception:
        sentinel_data = {}

    try:
        netpilot_data = ai_netpilot.get_status()
    except Exception:
        netpilot_data = {}

    try:
        schedules_data = db.get_schedules()
    except Exception:
        schedules_data = []

    try:
        timers_data = scheduler.get_active_timers()
    except Exception:
        timers_data = []

    try:
        routines_data = scheduler.get_routines_status()
    except Exception:
        routines_data = {}

    return {
        "type": "TICK",
        "timestamp": time.time(),
        "metrics": latest_metrics,
        "devices": devices,
        "apps": real_apps,
        "websites": real_sites,
        "intruders": intruders,
        "ghost_leaks": ghosts,
        "emergency_pause": emergency_pause,
        "kperf": kperf_metrics,
        "firewall": fw_metrics,
        "qos": qos_data,
        "stealth": stealth_data,
        "sentinel": sentinel_data,
        "netpilot": netpilot_data,
        "schedules": schedules_data,
        "timers": timers_data,
        "routines": routines_data,
        "ad_stats": {
            "total_blocked": ad_stats.get("total_blocked", 0),
            "total_queries": ad_stats.get("total_queries", 0)
        }
    }



async def get_telemetry_snapshot() -> Dict[str, Any]:
    """Asynchronous worker that runs CPU/IO-bound snapshot compilation without blocking event loop."""
    return await asyncio.to_thread(get_telemetry_snapshot_sync)


class WebSocketHub:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        
        # Immediately push the latest state to the newly connected client
        try:
            snapshot = await get_telemetry_snapshot()
            await websocket.send_text(json.dumps(snapshot))
        except Exception:
            pass

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        dead = []
        async with self._lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead.append(connection)

        if dead:
            async with self._lock:
                for d in dead:
                    self.active_connections.discard(d)

    async def broadcast_current_state(self):
        """Immediately broadcasts updated state to all connected clients."""
        if not self.active_connections:
            return
        snapshot = await get_telemetry_snapshot()
        await self.broadcast(snapshot)


ws_hub = WebSocketHub()


async def live_broadcast_task():
    """Continuous high-speed telemetry broadcast background worker (0.5s tick)."""
    while True:
        try:
            await asyncio.sleep(0.5)   # 2× faster updates for snappier UI
            if ws_hub.active_connections:
                snapshot = await get_telemetry_snapshot()
                await ws_hub.broadcast(snapshot)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.5)


from backend.core.activator import activator

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("==================================================")
    print("   🌐 SWITCHGATE - NETWORK GATEWAY CONTROLLER     ")
    print(f"   Gateway IP: {AppConfig.GATEWAY_IP}             ")
    print(f"   Local IP:   {AppConfig.LOCAL_IP}               ")
    print(f"   Web UI:     http://localhost:{AppConfig.PORT}  ")
    print("==================================================")
    
    activator.activate_all()
    broadcast_task = asyncio.create_task(live_broadcast_task())

    yield

    broadcast_task.cancel()
    activator.deactivate_all()


app = FastAPI(
    title=AppConfig.APP_NAME,
    version=AppConfig.APP_VERSION,
    description="The No-Code Network Gateway & Remote Control (kPerf Powered)",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=500)  # Compress responses > 500 bytes

from firewall.firewall_router import router as firewall_router
from backend.routers.auth import router as auth_router

app.include_router(devices_router)
app.include_router(apps_router)
app.include_router(websites_router)
app.include_router(kperf_router)
app.include_router(network_router)
app.include_router(adblock_router)
app.include_router(schedules_router)
app.include_router(intruders_router)
app.include_router(ghost_leaks_router)
app.include_router(settings_router)
app.include_router(firewall_router)
app.include_router(speedtest_router)
app.include_router(gemini_sentinel_router)
app.include_router(qos_router)
app.include_router(stealth_router)
app.include_router(ai_netpilot_router)
app.include_router(workspace_router)
app.include_router(auth_router)


@app.get("/health")
def health_check():
    """Ultra-fast, zero-overhead sub-millisecond health endpoint for desktop app bootstrap."""
    return {"status": "ok", "time": time.time()}


@app.get("/api/bootstrap")
async def get_bootstrap_payload():
    """Consolidated bootstrap payload returning network info, devices, apps, sites, settings, schedules, and active user in a single sub-10ms request."""
    snapshot = await get_telemetry_snapshot()
    settings = db.get_all_settings()
    current_user = db.get_current_user()
    network_info = {
        "gateway_ip": AppConfig.GATEWAY_IP,
        "local_ip": AppConfig.LOCAL_IP,
        "interface": AppConfig.NETWORK_INTERFACE
    }
    return {
        "telemetry": snapshot,
        "network_info": network_info,
        "settings": settings,
        "user": current_user
    }


@app.get("/api/telemetry/live", response_model=Dict[str, Any])
async def get_live_telemetry_bundle():
    """Unified Live Telemetry Endpoint: Returns full real-time snapshot for Fallback Polling & Diagnostics."""
    return await get_telemetry_snapshot()



@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                action = msg.get("action")
                if action == "PING":
                    await websocket.send_text(json.dumps({
                        "type": "PONG",
                        "client_ts": msg.get("timestamp"),
                        "server_ts": time.time()
                    }))
                elif action == "REQUEST_SYNC":
                    snapshot = await get_telemetry_snapshot()
                    await websocket.send_text(json.dumps(snapshot))
            except Exception:
                pass
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await ws_hub.disconnect(websocket)


frontend_dir = BUNDLE_DIR / "frontend"
if not frontend_dir.exists():
    frontend_dir = BASE_DIR / "frontend"

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

assets_dir = BUNDLE_DIR / "assets"
if not assets_dir.exists():
    assets_dir = BASE_DIR / "assets"

if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


@app.get("/")
async def serve_index():
    index_file = frontend_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "SwitchGate API is running."}


@app.get("/favicon.ico")
async def serve_favicon():
    icon_file = assets_dir / "icon.ico"
    if icon_file.exists():
        return FileResponse(icon_file)
    png_icon = assets_dir / "Square44x44Logo.png"
    if png_icon.exists():
        return FileResponse(png_icon)
    return JSONResponse(status_code=204, content=None)

