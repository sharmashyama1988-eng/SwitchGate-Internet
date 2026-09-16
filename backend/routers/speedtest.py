"""
SwitchGate - Built-in Internet Speed Test Router v2.1
Zero external tools, zero dependencies beyond httpx (async HTTP).
Tests download/upload speed against Cloudflare & fast.com endpoints.
Algorithm:
  - Download: Fetch 10MB file from Cloudflare, measure actual throughput
  - Upload: POST 5MB payload, measure round-trip
  - Latency: 5-ping ICMP-less RTT via HTTP HEAD requests
"""
import asyncio
import time
import socket
import statistics
from typing import Dict, Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/speedtest", tags=["Speed Test"])

# Test endpoints (CDN-backed, globally fast, license-free)
_DOWNLOAD_ENDPOINTS = [
    "https://speed.cloudflare.com/__down?bytes=5000000",   # 5 MB Cloudflare
    "https://speed.cloudflare.com/__down?bytes=2500000",   # 2.5 MB fallback
    "https://httpbin.org/bytes/2000000",                   # 2 MB fallback
]
_UPLOAD_ENDPOINT    = "https://speed.cloudflare.com/__up"
_LATENCY_ENDPOINT   = "https://1.1.1.1"

# ── Helpers ───────────────────────────────────────────────────────────────────

async def _measure_latency_ms(host: str = "1.1.1.1", port: int = 443, samples: int = 5) -> float:
    """Measures TCP handshake latency (more accurate than ICMP ping, no root needed)."""
    rtt_samples = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=3.0).close()),
                timeout=3.0
            )
            rtt_samples.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
        await asyncio.sleep(0.1)

    if not rtt_samples:
        return -1.0
    return round(statistics.median(rtt_samples), 2)


async def _measure_download_mbps() -> Dict[str, Any]:
    """
    Downloads a test payload from Cloudflare CDN and computes Mbps.
    Falls back through endpoint list until one succeeds.
    """
    try:
        import httpx
        for url in _DOWNLOAD_ENDPOINTS:
            try:
                t0 = time.perf_counter()
                async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    content_length = len(resp.content)
                elapsed = time.perf_counter() - t0

                if elapsed <= 0 or content_length < 1000:
                    continue

                mbps = round((content_length * 8) / (elapsed * 1_000_000), 2)
                return {
                    "mbps":       mbps,
                    "bytes":      content_length,
                    "elapsed_s":  round(elapsed, 3),
                    "endpoint":   url.split("//")[1].split("/")[0],
                    "success":    True
                }
            except Exception:
                continue
        return {"mbps": 0.0, "success": False, "error": "All download endpoints failed"}
    except ImportError:
        # httpx not installed — use urllib fallback
        return await _measure_download_urllib()


async def _measure_download_urllib() -> Dict[str, Any]:
    """Pure stdlib urllib fallback for download test (no httpx required)."""
    import urllib.request

    def _sync_download():
        url = _DOWNLOAD_ENDPOINTS[0]
        req = urllib.request.Request(url, headers={"User-Agent": "SwitchGate-SpeedTest/2.1"})
        t0  = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                elapsed = time.perf_counter() - t0
                mbps    = round((len(data) * 8) / (elapsed * 1_000_000), 2)
                return {"mbps": mbps, "bytes": len(data), "elapsed_s": round(elapsed, 3), "success": True}
        except Exception as e:
            return {"mbps": 0.0, "success": False, "error": str(e)}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_download)


async def _measure_upload_mbps() -> Dict[str, Any]:
    """
    Uploads a 5MB payload to Cloudflare speed test endpoint and measures upload throughput.
    """
    UPLOAD_SIZE_BYTES = 1024 * 1024  # 1 MB
    payload = b"0" * UPLOAD_SIZE_BYTES

    try:
        import httpx
        try:
            t0 = time.perf_counter()
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(_UPLOAD_ENDPOINT, content=payload, headers={
                    "Content-Type": "application/octet-stream",
                    "User-Agent":   "SwitchGate-SpeedTest/2.1"
                })
                elapsed = time.perf_counter() - t0

            if elapsed <= 0:
                return {"mbps": 0.0, "success": False, "error": "Zero elapsed"}

            mbps = round((UPLOAD_SIZE_BYTES * 8) / (elapsed * 1_000_000), 2)
            return {
                "mbps":      mbps,
                "bytes":     UPLOAD_SIZE_BYTES,
                "elapsed_s": round(elapsed, 3),
                "success":   True
            }
        except Exception as e:
            return {"mbps": 0.0, "success": False, "error": str(e)}
    except ImportError:
        # Urllib fallback
        return await _measure_upload_urllib(payload)


async def _measure_upload_urllib(payload: bytes) -> Dict[str, Any]:
    """Pure stdlib upload fallback."""
    import urllib.request

    def _sync_upload():
        try:
            req = urllib.request.Request(
                _UPLOAD_ENDPOINT,
                data=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "User-Agent":   "SwitchGate-SpeedTest/2.1"
                },
                method="POST"
            )
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
                elapsed = time.perf_counter() - t0
                mbps    = round((len(payload) * 8) / (elapsed * 1_000_000), 2)
                return {"mbps": mbps, "bytes": len(payload), "elapsed_s": round(elapsed, 3), "success": True}
        except Exception as e:
            return {"mbps": 0.0, "success": False, "error": str(e)}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_upload)


def _quality_label(down_mbps: float, latency_ms: float) -> str:
    """Returns a human-readable connection quality label."""
    if down_mbps <= 0:
        return "Offline / No Internet"
    if down_mbps >= 100 and latency_ms < 20:
        return "🚀 Fiber / Gigabit"
    if down_mbps >= 50 and latency_ms < 30:
        return "⚡ Excellent"
    if down_mbps >= 25 and latency_ms < 50:
        return "✅ Very Good"
    if down_mbps >= 10 and latency_ms < 80:
        return "👍 Good"
    if down_mbps >= 5 and latency_ms < 150:
        return "⚠️ Fair"
    if down_mbps >= 1:
        return "🐢 Slow"
    return "❌ Very Slow"

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/run")
async def run_speed_test() -> Dict[str, Any]:
    """
    Runs a full internet speed test: download, upload, latency.
    Takes approximately 15-25 seconds depending on connection speed.
    Returns JSON with all metrics and a quality label.
    """
    t_start = time.time()

    # Run measurements in sequence to prevent bandwidth contention
    latency_ms    = await _measure_latency_ms()
    download_info = await _measure_download_mbps()
    upload_info   = await _measure_upload_mbps()

    total_duration = round(time.time() - t_start, 1)

    down_mbps = download_info.get("mbps", 0.0)
    up_mbps   = upload_info.get("mbps",   0.0)

    return {
        "status":          "ok",
        "timestamp":       time.time(),
        "total_duration_s": total_duration,
        "download": {
            "mbps":        down_mbps,
            "mbps_str":    f"{down_mbps:.1f} Mbps",
            "bytes_tested": download_info.get("bytes", 0),
            "elapsed_s":   download_info.get("elapsed_s", 0),
            "success":     download_info.get("success", False),
        },
        "upload": {
            "mbps":        up_mbps,
            "mbps_str":    f"{up_mbps:.1f} Mbps",
            "bytes_tested": upload_info.get("bytes", 0),
            "elapsed_s":   upload_info.get("elapsed_s", 0),
            "success":     upload_info.get("success", False),
        },
        "latency": {
            "ms":          latency_ms,
            "ms_str":      f"{latency_ms:.1f} ms" if latency_ms >= 0 else "N/A",
            "success":     latency_ms >= 0,
        },
        "quality":     _quality_label(down_mbps, latency_ms),
        "server":      "Cloudflare CDN",
    }


@router.get("/ping")
async def quick_ping() -> Dict[str, Any]:
    """Quick latency-only measurement (fast, ~1-2 seconds)."""
    latency_ms = await _measure_latency_ms(samples=3)
    return {
        "latency_ms": latency_ms,
        "ms_str":     f"{latency_ms:.1f} ms" if latency_ms >= 0 else "N/A",
        "status":     "ok" if latency_ms >= 0 else "error"
    }
