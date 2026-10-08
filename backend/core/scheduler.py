"""
SwitchGate - Smart Time-Scheduler & Autonomous Network Automation Daemon v2.0
Enforces Bedtime Cutoffs, Sleep Countdown Timers, Periodic Network Discovery Sweeps,
and Autonomous AI Security Sentinel Audits with Sub-Second Precision.
"""
import time
import datetime
import threading
from typing import Optional, Dict, Any, List

from backend.database import db
from backend.core.blocker import blocker


class SmartTimeScheduler:
    def __init__(self):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._schedule_blocked_macs: set = set()
        self._warning_notified_macs: set = set()
        self._lock = threading.Lock()

        # Routine tracking timestamps
        self._last_auto_scan_ts: float = time.time()
        self._last_auto_audit_ts: float = time.time()
        self._cached_timers: Dict[str, Dict[str, Any]] = {}

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
            self._sync_timers_from_db()
            self._thread = threading.Thread(target=self._scheduler_loop, daemon=True, name="SwitchGate-Scheduler")
            self._thread.start()
            print("[Scheduler] ⏳ Smart Time-Scheduler & Network Automation Daemon active (5s precision).")

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=1.5)
            except Exception:
                pass
        print("[Scheduler] Smart Time-Scheduler Daemon stopped.")

    def _sync_timers_from_db(self):
        """Loads non-expired countdown timers from persistent SQLite database."""
        try:
            now_ts = time.time()
            db.cleanup_expired_timers(now_ts)
            timers = db.get_countdown_timers()
            with self._lock:
                self._cached_timers.clear()
                for t in timers:
                    mac = t["mac"].lower().replace("-", ":")
                    self._cached_timers[mac] = {
                        "mac": mac,
                        "name": t.get("name", ""),
                        "action": t.get("action", "BLOCK"),
                        "duration_minutes": t.get("duration_minutes", 15),
                        "expires_at": float(t.get("expires_at", 0)),
                        "created_at": float(t.get("created_at", now_ts))
                    }
        except Exception as e:
            print(f"[Scheduler Sync Error] {e}")

    def _scheduler_loop(self):
        """Main evaluation loop executing every 5 seconds."""
        while not self._stop_event.is_set():
            try:
                self.evaluate_countdown_timers()
                self.evaluate_schedules()
                self.evaluate_autonomous_routines()
            except Exception as e:
                print(f"[Scheduler Cycle Error] {e}")

            if self._stop_event.wait(timeout=5.0):
                break

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Countdown Sleep Timers (e.g. 15m, 30m, 1h, 2h)
    # ─────────────────────────────────────────────────────────────────────────

    def add_countdown_timer(self, mac: str, duration_minutes: int, action: str = "BLOCK", name: str = "") -> Dict[str, Any]:
        """Sets a high-precision countdown sleep timer for a specific device."""
        mac = mac.lower().replace("-", ":")
        now_ts = time.time()
        expires_at = now_ts + (duration_minutes * 60)

        dev = db.get_device(mac)
        dev_name = dev.get("custom_name", mac) if dev else mac
        if not name:
            name = dev_name

        timer_obj = {
            "mac": mac,
            "name": name,
            "action": action.upper(),
            "duration_minutes": duration_minutes,
            "expires_at": expires_at,
            "created_at": now_ts
        }

        with self._lock:
            self._cached_timers[mac] = timer_obj

        # Persist to database
        db.add_countdown_timer(mac, name, action.upper(), duration_minutes, expires_at)
        db.add_log(
            "TIMER_CREATED",
            mac,
            dev.get("ip", "") if dev else "",
            f"Sleep Timer Activated: {duration_minutes} min ({action.upper()}) for {name}"
        )

        self._notify_state_change()
        print(f"[Scheduler] ⏱️ Sleep timer set for {name} ({mac}) - {duration_minutes} mins (Action: {action})")
        return self._format_timer(timer_obj)

    def cancel_countdown_timer(self, mac: str) -> bool:
        """Cancels an active countdown sleep timer."""
        mac = mac.lower().replace("-", ":")
        with self._lock:
            if mac in self._cached_timers:
                del self._cached_timers[mac]
        db.delete_countdown_timer(mac)
        db.add_log("TIMER_CANCELLED", mac, "", f"Sleep Timer cancelled for {mac}")
        self._notify_state_change()
        print(f"[Scheduler] ⏱️ Sleep timer cancelled for {mac}")
        return True

    def get_active_timers(self) -> List[Dict[str, Any]]:
        """Returns list of active timers enriched with device details and remaining seconds."""
        now_ts = time.time()
        results = []
        with self._lock:
            active_list = list(self._cached_timers.values())

        for t in active_list:
            if t["expires_at"] > now_ts:
                results.append(self._format_timer(t, now_ts))
        return results

    def _format_timer(self, timer_obj: Dict[str, Any], now_ts: Optional[float] = None) -> Dict[str, Any]:
        if now_ts is None:
            now_ts = time.time()
        mac = timer_obj["mac"]
        expires_at = timer_obj["expires_at"]
        created_at = timer_obj.get("created_at", now_ts)
        total_seconds = max(1.0, (expires_at - created_at))
        rem_seconds = max(0, int(expires_at - now_ts))

        mins = rem_seconds // 60
        secs = rem_seconds % 60
        formatted = f"{mins:02d}:{secs:02d}"

        # Calculate progress percent (100% at start, 0% at expiration)
        progress = max(0.0, min(100.0, (rem_seconds / total_seconds) * 100))

        dev = db.get_device(mac)
        return {
            "mac": mac,
            "name": timer_obj.get("name", dev.get("custom_name", mac) if dev else mac),
            "ip": dev.get("ip", "") if dev else "",
            "device_type": dev.get("device_type", "unknown") if dev else "unknown",
            "action": timer_obj.get("action", "BLOCK"),
            "duration_minutes": timer_obj.get("duration_minutes", 15),
            "expires_at": expires_at,
            "remaining_seconds": rem_seconds,
            "remaining_formatted": formatted,
            "progress_percent": round(progress, 1),
            "is_blocked": bool(dev.get("is_blocked", 0)) if dev else False
        }

    def evaluate_countdown_timers(self):
        """Evaluates whether any countdown sleep timers have elapsed."""
        now_ts = time.time()
        expired_macs = []

        with self._lock:
            for mac, timer in list(self._cached_timers.items()):
                if timer["expires_at"] <= now_ts:
                    expired_macs.append((mac, timer))

        for mac, timer in expired_macs:
            action = timer.get("action", "BLOCK").upper()
            dev = db.get_device(mac)
            dev_ip = dev.get("ip", "") if dev else ""
            dev_name = timer.get("name", dev.get("custom_name", mac) if dev else mac)

            print(f"[Scheduler] 🔔 Sleep Timer EXPIRED for {dev_name} ({mac}) -> Executing {action}")

            if action == "BLOCK":
                if dev_ip:
                    blocker.block_device(mac, dev_ip)
                db.update_dual_switches(mac, left_on=False)
                db.add_log(
                    "TIMER_EXPIRED",
                    mac,
                    dev_ip,
                    f"Sleep Timer Expired ({timer.get('duration_minutes')}m): Access Paused for {dev_name}"
                )
            elif action == "RESTORE":
                if dev_ip:
                    blocker.unblock_device(mac, dev_ip)
                db.update_dual_switches(mac, left_on=True)
                db.add_log(
                    "TIMER_EXPIRED",
                    mac,
                    dev_ip,
                    f"Sleep Timer Expired: Access Restored for {dev_name}"
                )

            with self._lock:
                self._cached_timers.pop(mac, None)
            db.delete_countdown_timer(mac)
            self._notify_state_change()

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Recurring Bedtime Curfews & Access Windows
    # ─────────────────────────────────────────────────────────────────────────

    def evaluate_schedules(self):
        """Enforces recurring bedtime windows and automatic restoration."""
        schedules = db.get_schedules()
        if not schedules:
            return

        now = datetime.datetime.now()
        current_time_str = now.strftime("%H:%M")
        current_day_str = now.strftime("%a").upper() # 'MON', 'TUE', 'WED', etc.
        is_weekend = current_day_str in ["SAT", "SUN"]

        for rule in schedules:
            if not rule.get("is_active"):
                continue

            mac = rule.get("mac", "").lower().replace("-", ":")
            start = rule.get("start_time", "00:00")
            end = rule.get("end_time", "00:00")
            days = rule.get("days", "ALL").upper()

            if not mac:
                continue

            # Check day filter: ALL, WEEKDAYS, WEEKENDS, or MON,TUE...
            if not self._is_day_active(current_day_str, is_weekend, days):
                continue

            dev = db.get_device(mac)
            if not dev:
                continue

            dev_ip = dev.get("ip", "")
            dev_name = dev.get("custom_name", mac)
            is_in_cutoff = self._is_time_between(current_time_str, start, end)

            # Pre-cutoff warning check (5 minutes before cutoff)
            self._check_pre_cutoff_warning(mac, dev_name, current_time_str, start)

            # 1. Auto-Cutoff Enforcement
            if is_in_cutoff and not dev.get("is_blocked"):
                print(f"[Scheduler] 🕒 Bedtime Curfew Enforced for {dev_name} ({mac}) [{start} - {end}]")
                if dev_ip:
                    blocker.block_device(mac, dev_ip)
                db.update_dual_switches(mac, left_on=False)
                db.add_log(
                    "SCHEDULE_CUTOFF",
                    mac,
                    dev_ip,
                    f"Smart Scheduler: Curfew Enforced ({start} - {end}) for {dev_name}"
                )
                with self._lock:
                    self._schedule_blocked_macs.add(mac)
                self._notify_state_change()

            # 2. Auto-Restore Outside Window
            elif not is_in_cutoff:
                with self._lock:
                    was_schedule_blocked = mac in self._schedule_blocked_macs

                if was_schedule_blocked and dev.get("is_blocked"):
                    # Respect manual emergency pause and bans
                    if dev.get("is_banned") or db.get_setting("emergency_pause_active") == "1":
                        continue
                    print(f"[Scheduler] 🕒 Bedtime Curfew Ended - Restoring {dev_name} ({mac})")
                    if dev_ip:
                        blocker.unblock_device(mac, dev_ip)
                    db.update_dual_switches(mac, left_on=True)
                    db.add_log(
                        "SCHEDULE_RESTORE",
                        mac,
                        dev_ip,
                        f"Smart Scheduler: Access Restored (Outside {start} - {end}) for {dev_name}"
                    )
                    with self._lock:
                        self._schedule_blocked_macs.discard(mac)
                    self._notify_state_change()

    def _is_day_active(self, current_day: str, is_weekend: bool, days_setting: str) -> bool:
        if days_setting in ["ALL", "EVERYDAY", "DAILY"]:
            return True
        if days_setting in ["WEEKDAYS", "MON-FRI"]:
            return not is_weekend
        if days_setting in ["WEEKENDS", "SAT-SUN"]:
            return is_weekend
        # Comma-separated or substring check e.g. "MON,TUE,WED"
        return current_day in days_setting

    def _is_time_between(self, current: str, start: str, end: str) -> bool:
        """Handles both same-day (e.g. 14:00 - 16:00) and overnight windows (e.g. 22:00 - 06:00)."""
        if start <= end:
            return start <= current < end
        else:
            return current >= start or current < end

    def _check_pre_cutoff_warning(self, mac: str, dev_name: str, current: str, start: str):
        """Emits a warning 5 minutes before scheduled disconnect."""
        try:
            curr_h, curr_m = map(int, current.split(":"))
            start_h, start_m = map(int, start.split(":"))
            curr_mins = curr_h * 60 + curr_m
            start_mins = start_h * 60 + start_m
            diff = (start_mins - curr_mins) % (24 * 60)

            if diff == 5:
                warn_key = f"{mac}_{start}"
                with self._lock:
                    if warn_key not in self._warning_notified_macs:
                        self._warning_notified_macs.add(warn_key)
                        db.add_log("SCHEDULE_WARNING", mac, "", f"Curfew Alert: Internet for {dev_name} will pause in 5 minutes ({start}).")
            elif diff > 10:
                warn_key = f"{mac}_{start}"
                with self._lock:
                    self._warning_notified_macs.discard(warn_key)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Autonomous Network Routines (Discovery, AI Audit, Auto-Quarantine)
    # ─────────────────────────────────────────────────────────────────────────

    def evaluate_autonomous_routines(self):
        """Runs background autonomous sweeps at configured intervals."""
        now_ts = time.time()

        # Routine A: Periodic Network Discovery Sweep (Default: every 15 mins)
        auto_scan_enabled = db.get_setting("auto_scan_enabled", "1") == "1"
        scan_interval_sec = int(db.get_setting("auto_scan_interval_mins", "15")) * 60
        if auto_scan_enabled and (now_ts - self._last_auto_scan_ts >= scan_interval_sec):
            self._last_auto_scan_ts = now_ts
            threading.Thread(target=self._run_background_scan, daemon=True, name="SwitchGate-AutoScan").start()

        # Routine B: Periodic AI Threat Audit (Default: every 12 hours)
        auto_audit_enabled = db.get_setting("auto_audit_enabled", "1") == "1"
        audit_interval_sec = int(db.get_setting("auto_audit_interval_hours", "12")) * 3600
        if auto_audit_enabled and (now_ts - self._last_auto_audit_ts >= audit_interval_sec):
            self._last_auto_audit_ts = now_ts
            threading.Thread(target=self._run_background_audit, daemon=True, name="SwitchGate-AutoAudit").start()

        # Routine C: Auto-Quarantine Watchdog for Rogue Intruders
        if db.get_setting("auto_quarantine", "0") == "1":
            self._enforce_auto_quarantine()

    def _run_background_scan(self):
        try:
            print("[Scheduler] 🌐 Triggering autonomous background network sweep...")
            from backend.core.scanner import scanner
            scanner.scan_network()
        except Exception as e:
            print(f"[Scheduler AutoScan Error] {e}")

    def _run_background_audit(self):
        try:
            print("[Scheduler] 🛡️ Triggering autonomous AI network security audit...")
            from backend.core.gemini_sentinel import gemini_sentinel
            gemini_sentinel.analyze_network(force_heuristic=False)
        except Exception as e:
            print(f"[Scheduler AutoAudit Error] {e}")

    def _enforce_auto_quarantine(self):
        """Automatically isolates pending unknown intruders if auto_quarantine is active."""
        try:
            pending = db.get_pending_intruders()
            for intr in pending:
                mac = intr.get("mac", "")
                if mac and not intr.get("is_trusted"):
                    db.ban_intruder(mac)
                    dev = db.get_device(mac)
                    ip = dev.get("ip", "") if dev else intr.get("ip", "")
                    vendor = intr.get("vendor", "Unknown Hardware")
                    if ip:
                        blocker.block_device(mac, ip)
                    db.add_log("AUTO_QUARANTINE", mac, ip, f"Rogue device {mac} ({vendor}) quarantined automatically.")
                    print(f"[Scheduler] 🚨 Auto-Quarantined rogue device: {mac}")

                    # Google Workspace Alert Dispatch
                    if db.get_setting("gworkspace_auto_alert_intruders", "1") == "1":
                        try:
                            from backend.core.google_workspace_bridge import workspace_bridge
                            workspace_bridge.dispatch_workspace_alert(
                                title="Rogue Intruder Quarantined",
                                message=f"Unauthorized device detected and instantly quarantined on local network:\n- MAC: {mac}\n- IP: {ip}\n- Vendor: {vendor}",
                                alert_type="DANGER"
                            )
                        except Exception:
                            pass

                    self._notify_state_change()
        except Exception as e:
            print(f"[Scheduler Quarantine Error] {e}")

    def get_routines_status(self) -> Dict[str, Any]:
        """Returns live status of all background autonomous tasks."""
        now_ts = time.time()
        scan_int_mins = int(db.get_setting("auto_scan_interval_mins", "15"))
        audit_int_hrs = int(db.get_setting("auto_audit_interval_hours", "12"))

        scan_next_sec = max(0, int((self._last_auto_scan_ts + (scan_int_mins * 60)) - now_ts))
        audit_next_sec = max(0, int((self._last_auto_audit_ts + (audit_int_hrs * 3600)) - now_ts))

        return {
            "auto_scan": {
                "enabled": db.get_setting("auto_scan_enabled", "1") == "1",
                "interval_mins": scan_int_mins,
                "next_in_seconds": scan_next_sec,
                "next_formatted": f"{scan_next_sec // 60}m {scan_next_sec % 60}s"
            },
            "auto_audit": {
                "enabled": db.get_setting("auto_audit_enabled", "1") == "1",
                "interval_hours": audit_int_hrs,
                "next_in_seconds": audit_next_sec,
                "next_formatted": f"{audit_next_sec // 3600}h {(audit_next_sec % 3600) // 60}m"
            },
            "auto_quarantine": {
                "enabled": db.get_setting("auto_quarantine", "0") == "1"
            }
        }

    def _notify_state_change(self):
        try:
            from backend.main import ws_hub
            import asyncio
            asyncio.create_task(ws_hub.broadcast_current_state())
        except Exception:
            pass


scheduler = SmartTimeScheduler()
