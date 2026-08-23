"""
CrashPad - UI & Input Management (Throttling, Debouncing, Single-Task Pattern)
Protects against rapid spam clicking, duplicate submissions, and screen overlapping.
"""
import time
import asyncio
import functools
import threading
from typing import Callable, Any, Dict, Optional, Tuple

class Throttle:
    """
    Throttling Algorithm: Accepts only the FIRST execution in a given time window (e.g. 1.0s).
    Subsequent invocations within the cooldown window are dropped or return cached result.
    """
    def __init__(self, interval: float = 1.0, return_last_result: bool = False):
        self.interval = interval
        self.return_last_result = return_last_result
        self.last_called: float = 0.0
        self.last_result: Any = None
        self._lock = threading.Lock()

    def __call__(self, fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            now = time.time()
            with self._lock:
                if now - self.last_called >= self.interval:
                    self.last_called = now
                    self.last_result = fn(*args, **kwargs)
                    return self.last_result
                elif self.return_last_result:
                    return self.last_result
                return None
        return wrapper

class Debounce:
    """
    Debouncing Algorithm: Delays execution until the user STOPS typing/clicking for `wait` seconds.
    Executes only the LAST invocation after the quiet period.
    """
    def __init__(self, wait: float = 0.3):
        self.wait = wait
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def __call__(self, fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with self._lock:
                if self._timer is not None:
                    self._timer.cancel()
                self._timer = threading.Timer(self.wait, lambda: fn(*args, **kwargs))
                self._timer.daemon = True
                self._timer.start()
        return wrapper

class SingleTaskRunner:
    """
    Single-Task / LaunchMode / Single-Flight Pattern:
    Ensures that only ONE instance of a specific task, screen, or computation runs at any time.
    Duplicate concurrent requests share the same in-flight execution or are cleanly de-duplicated.
    """
    def __init__(self):
        self._active_tasks: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._async_lock = asyncio.Lock() if asyncio else None

    def execute_sync(self, task_key: str, fn: Callable, *args, **kwargs) -> Tuple[bool, Any]:
        """Runs synchronous task if not already in flight. Returns (executed, result)."""
        with self._lock:
            if task_key in self._active_tasks:
                return (False, None) # Task is already running (deduplicated)
            self._active_tasks[task_key] = True

        try:
            result = fn(*args, **kwargs)
            return (True, result)
        finally:
            with self._lock:
                self._active_tasks.pop(task_key, None)

    async def execute_async(self, task_key: str, coro_fn: Callable, *args, **kwargs) -> Any:
        """Asynchronous Single-Flight: If task is running, waits for the existing Future instead of re-executing."""
        # Check active future
        future = None
        with self._lock:
            if task_key in self._active_tasks:
                future = self._active_tasks[task_key]

        if future is not None:
            return await future

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        with self._lock:
            self._active_tasks[task_key] = future

        try:
            res = await coro_fn(*args, **kwargs)
            future.set_result(res)
            return res
        except Exception as e:
            future.set_exception(e)
            raise e
        finally:
            with self._lock:
                self._active_tasks.pop(task_key, None)

def throttle(seconds: float = 1.0):
    return Throttle(interval=seconds)

def debounce(seconds: float = 0.3):
    return Debounce(wait=seconds)
