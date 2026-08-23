"""
CrashPad - Error & Fallback Grace (Global Exception Guardian, Graceful Degradation)
Catches unhandled errors, logs diagnostics, and degrades gracefully instead of crashing.
"""
import os
import sys
import time
import tempfile
import traceback
import functools
import threading
import asyncio
from pathlib import Path
from typing import Callable, Any, Optional, Dict, List

class GlobalExceptionGuardian:
    """
    Global Exception Guardian:
    Hooks into `sys.excepthook` and `threading.excepthook` to intercept fatal unhandled crashes,
    persisting crash traces to `data/crash_logs/` while keeping critical background daemons alive.
    """
    def __init__(self, log_dir: Optional[Path] = None):
        if log_dir is None:
            import tempfile
            app_data_root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
            log_dir = Path(app_data_root) / "SwitchGate" / "data" / "crash_logs"
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._installed = False

    def install(self):
        if self._installed:
            return
        self._installed = True

        def _sys_hook(exc_type, exc_value, exc_traceback):
            self.record_crash("UNHANDLED_EXCEPTION", exc_type, exc_value, exc_traceback)

        def _thread_hook(args):
            self.record_crash("UNHANDLED_THREAD_EXCEPTION", args.exc_type, args.exc_value, args.exc_traceback)

        sys.excepthook = _sys_hook
        if hasattr(threading, "excepthook"):
            threading.excepthook = _thread_hook
        print("[CrashPad Guardian] Global Exception Guardian active.")

    def record_crash(self, category: str, exc_type, exc_value, exc_traceback):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"crash_{timestamp}.log"
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        content = f"=== CRASHPAD INCIDENT REPORT: {category} ===\nTime: {time.ctime()}\n\n" + "".join(tb_lines)

        try:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[CrashPad Guardian] Intercepted crash! Log saved: {log_file.name}")
        except Exception:
            pass

class GracefulDegradation:
    """
    Graceful Degradation Pattern:
    Executes primary logic, and if it fails or timeouts, seamlessly falls back to a lightweight,
    safe static response or procedural fallback instead of crashing the UI or API.
    """
    @staticmethod
    def wrap(primary_fn: Callable, fallback_fn_or_value: Any, expected_exceptions: tuple = (Exception,)) -> Callable:
        if asyncio.iscoroutinefunction(primary_fn):
            @functools.wraps(primary_fn)
            async def async_degraded(*args, **kwargs):
                try:
                    return await primary_fn(*args, **kwargs)
                except expected_exceptions:
                    if callable(fallback_fn_or_value):
                        if asyncio.iscoroutinefunction(fallback_fn_or_value):
                            return await fallback_fn_or_value(*args, **kwargs)
                        return fallback_fn_or_value(*args, **kwargs)
                    return fallback_fn_or_value
            return async_degraded
        else:
            @functools.wraps(primary_fn)
            def sync_degraded(*args, **kwargs):
                try:
                    return primary_fn(*args, **kwargs)
                except expected_exceptions:
                    if callable(fallback_fn_or_value):
                        return fallback_fn_or_value(*args, **kwargs)
                    return fallback_fn_or_value
            return sync_degraded

def safe_fallback(fallback_value: Any):
    """Decorator that returns `fallback_value` on any unhandled exception."""
    def decorator(fn: Callable):
        return GracefulDegradation.wrap(fn, fallback_value)
    return decorator
