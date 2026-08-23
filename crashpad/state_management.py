"""
CrashPad - State & Background Handling (State Restoration / SaveInstance, Heartbeat Monitor)
Ensures persistent recovery across app restarts, background suspends, and socket drops.
"""
import os
import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Callable

class StateRestorationManager:
    """
    State Restoration (SaveInstanceState / Crash Recovery):
    Persists atomic state snapshots to a recovery file.
    If the app or OS kills the process, the saved state is seamlessly restored on relaunch.
    """
    def __init__(self, state_file_path: Optional[Path] = None):
        if state_file_path is None:
            import tempfile
            app_data_root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
            state_file_path = Path(app_data_root) / "SwitchGate" / "data" / "crashpad_state.json"
        self.state_file_path = Path(state_file_path)
        try:
            self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._cached_state: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self.load_snapshot()

    def set_key(self, key: str, value: Any, auto_save: bool = True) -> None:
        with self._lock:
            self._cached_state[key] = value
        if auto_save:
            self.save_snapshot()

    def get_key(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._cached_state.get(key, default)

    def save_snapshot(self) -> bool:
        """Atomic snapshot write via temporary file replace to prevent corrupt state files."""
        temp_file = self.state_file_path.with_suffix(".tmp")
        try:
            with self._lock:
                data_copy = dict(self._cached_state)
            
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data_copy, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            temp_file.replace(self.state_file_path)
            return True
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False

    def load_snapshot(self) -> Dict[str, Any]:
        if not self.state_file_path.exists():
            return {}
        try:
            with open(self.state_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                self._cached_state = data
            return data
        except Exception:
            return {}

class HeartbeatMonitor:
    """
    Heartbeat / Ping Monitor:
    Sends periodic pings across background sockets/threads.
    If no response is received within `timeout_seconds`, triggers reconnect / recovery callback.
    """
    def __init__(
        self,
        interval_seconds: float = 3.0,
        timeout_seconds: float = 10.0,
        on_timeout_callback: Optional[Callable[[], None]] = None
    ):
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds
        self.on_timeout_callback = on_timeout_callback
        self.last_heartbeat = time.time()
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.last_heartbeat = time.time()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="CrashPad-Heartbeat")
        self._thread.start()

    def stop(self):
        self.is_running = False

    def record_pulse(self):
        """Called whenever a valid message / packet / pong arrives from the peer."""
        with self._lock:
            self.last_heartbeat = time.time()

    def is_alive(self) -> bool:
        with self._lock:
            return (time.time() - self.last_heartbeat) < self.timeout_seconds

    def _monitor_loop(self):
        while self.is_running:
            time.sleep(self.interval_seconds)
            with self._lock:
                elapsed = time.time() - self.last_heartbeat

            if elapsed >= self.timeout_seconds:
                if self.on_timeout_callback:
                    try:
                        self.on_timeout_callback()
                    except Exception:
                        pass
                # Reset timer after firing callback
                with self._lock:
                    self.last_heartbeat = time.time()
