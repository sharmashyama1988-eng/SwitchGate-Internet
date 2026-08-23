"""
SwitchGate - kPerf Kernel Hypervisor REST API Router
Provides real-time ring buffer telemetry, zero-copy packet shadow counters, and circuit breaker metrics.
"""
from fastapi import APIRouter
from typing import Dict, Any

from backend.kperf.kperf_engine import kperf_engine

router = APIRouter(prefix="/api/kperf", tags=["kPerf Kernel Hypervisor"])

@router.get("/metrics", response_model=Dict[str, Any])
async def get_kperf_metrics():
    """Returns 60 FPS real-time hypervisor telemetry and lock-free ring buffer status."""
    return kperf_engine.get_metrics()
