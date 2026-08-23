"""
SwitchGate - Smart Time-Scheduler Daemon (Bedtime & Access Rules)
Runs periodic checks every 30 seconds to automatically enforce bedtime cutoff and restore rules.
"""
import time
import datetime
import threading
from typing import Optional
from backend.database import db
from backend.core.blocker import blocker

class SmartTimeScheduler:
    def __init__(self):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._schedule_blocked_macs: set = set()
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._scheduler_loop, daemon=True, name="SwitchGate-Scheduler")
            self._thread.start()
            print("[Scheduler] Smart Time-Scheduler Daemon active.")

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass

    def _scheduler_loop(self):
        while not self._stop_event.is_set():
            try:
                self.evaluate_schedules()
            except Exception as e:
                print(f"[Scheduler Error] {e}")
            if self._stop_event.wait(timeout=30):
                break

    def evaluate_schedules(self):
        schedules = db.get_schedules()
        if not schedules:
            return

        now = datetime.datetime.now()
        current_time_str = now.strftime("%H:%M")
        current_day_str = now.strftime("%a").upper() # 'MON', 'TUE', etc.

        for rule in schedules:
            if not rule.get("is_active"):
                continue

            mac = rule.get("mac", "").lower().replace("-", ":")
            start = rule.get("start_time", "00:00")
            end = rule.get("end_time", "00:00")
            days = rule.get("days", "ALL").upper()

            if not mac:
                continue

            # Check if today is active
            if days != "ALL" and current_day_str not in days:
                continue

            dev = db.get_device(mac)
            if not dev:
                continue

            dev_ip = dev.get("ip", "")
            dev_name = dev.get("custom_name", mac)
            is_in_cutoff = self._is_time_between(current_time_str, start, end)

            # If in cutoff window and device is currently online -> Auto-Cutoff
            if is_in_cutoff and not dev.get("is_blocked"):
                print(f"[Scheduler] 🕒 Bedtime Cutoff Triggered for {dev_name} ({mac})")
                blocker.block_device(mac, dev_ip)
                db.update_dual_switches(mac, left_on=False)
                db.add_log("SCHEDULE_CUTOFF", mac, dev_ip, f"Smart Scheduler: Bedtime Cutoff Enforced ({start} - {end})")
                with self._lock:
                    self._schedule_blocked_macs.add(mac)

            # If outside cutoff window and device was blocked specifically by schedule -> Auto-Restore
            elif not is_in_cutoff:
                with self._lock:
                    was_schedule_blocked = mac in self._schedule_blocked_macs

                if was_schedule_blocked and dev.get("is_blocked"):
                    # Check if emergency pause or banned
                    if dev.get("is_banned") or db.get_setting("emergency_pause_active") == "1":
                        continue
                    print(f"[Scheduler] 🕒 Bedtime Ended - Restoring {dev_name} ({mac})")
                    blocker.unblock_device(mac, dev_ip)
                    db.update_dual_switches(mac, left_on=True)
                    db.add_log("SCHEDULE_RESTORE", mac, dev_ip, f"Smart Scheduler: Access Restored (Outside {start} - {end})")
                    with self._lock:
                        self._schedule_blocked_macs.discard(mac)

    def _is_time_between(self, current: str, start: str, end: str) -> bool:
        """Handles both same-day (e.g. 14:00 - 16:00) and overnight windows (e.g. 22:00 - 06:00)."""
        if start <= end:
            return start <= current < end
        else: # Overnight window (e.g. 22:00 to 06:00)
            return current >= start or current < end

scheduler = SmartTimeScheduler()
