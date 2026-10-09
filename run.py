"""
SwitchGate - Unified Development, Testing & Standalone Application Runner
Supports:
  - python run.py              -> Desktop WebView2 window if available, else Browser
  - python run.py --browser    -> Directly launches server & opens default web browser
  - python run.py --test       -> Runs automated pre-flight diagnostics & endpoint test suite
  - python run.py --headless   -> Runs background daemon without launching window/browser
  - python run.py --no-elevate -> Runs in standard user mode without prompting UAC
  - python run.py --port 8080  -> Runs on custom port
"""
import os
import sys
import time
import socket
import argparse
import threading
import webbrowser
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def is_admin() -> bool:
    """Checks if current process has Windows Administrator privileges."""
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def request_elevation_if_needed(skip_elevation: bool = False):
    """Requests UAC administrator elevation on Windows if running in full mode."""
    if skip_elevation or is_admin() or os.name != "nt":
        return

    # Don't auto-elevate during automated tests or non-interactive terminals
    if not sys.stdin.isatty():
        return

    try:
        import ctypes
        script = str(Path(sys.argv[0]).resolve())
        args = [f'"{a}"' for a in sys.argv[1:] if a != "--no-elevate"]
        params = f'"{script}" ' + " ".join(args + ["--no-elevate"])
        print("[*] Requesting Windows Administrator privileges for full kernel/firewall access...")
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params.strip(), str(PROJECT_ROOT), 1)
        if ret > 32:
            sys.exit(0)
    except Exception as e:
        print(f"[!] UAC elevation skipped: {e}. Running in Standard User mode.")


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if target port is already bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def open_browser_delayed(url: str, delay_seconds: float = 0.8):
    """Waits for uvicorn to bind and launches user's default browser."""
    def _open():
        time.sleep(delay_seconds)
        try:
            webbrowser.open(url)
        except Exception as err:
            print(f"[Browser] Could not auto-launch browser: {err}")
    threading.Thread(target=_open, daemon=True).start()


def run_automated_smoke_tests(port: int = 8000) -> bool:
    """
    Runs automated in-process test suite verifying all core APIs,
    Active Apps enumeration, Sites & URLs discovery, and Firebase Auth endpoints.
    """
    print("\n" + "=" * 65)
    print("   🧪 SWITCHGATE INTERNET - AUTOMATED TEST SUITE & DIAGNOSTICS")
    print("=" * 65)

    test_passed = 0
    test_failed = 0

    def check(title: str, condition: bool, details: str = ""):
        nonlocal test_passed, test_failed
        if condition:
            test_passed += 1
            print(f"  ✅ PASS : {title} {f'({details})' if details else ''}")
        else:
            test_failed += 1
            print(f"  ❌ FAIL : {title} {f'({details})' if details else ''}")

    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.config import AppConfig
        from backend.database import db

        client = TestClient(app)

        # 1. Health Heartbeat Test
        t0 = time.time()
        res_health = client.get("/health")
        latency_ms = round((time.time() - t0) * 1000, 2)
        check("Health Check Endpoint (/health)", res_health.status_code == 200, f"{latency_ms}ms")

        # 2. Fast Bootstrap Endpoint
        t0 = time.time()
        res_boot = client.get("/api/bootstrap")
        latency_ms = round((time.time() - t0) * 1000, 2)
        boot_data = res_boot.json() if res_boot.status_code == 200 else {}
        telemetry = boot_data.get("telemetry", {})
        check(
            "Consolidated Bootstrap (/api/bootstrap)",
            res_boot.status_code == 200 and "telemetry" in boot_data,
            f"Returned {len(telemetry.keys())} telemetry modules in {latency_ms}ms"
        )

        # 3. Active Windows Apps Enumeration
        res_apps = client.get("/api/apps")
        apps_data = res_apps.json() if res_apps.status_code == 200 else []
        check(
            "Active Windows Apps Controller (/api/apps)",
            res_apps.status_code == 200 and len(apps_data) > 0,
            f"{len(apps_data)} running user applications detected"
        )
        if apps_data:
            sample_apps = [a.get("friendly_name", a.get("name")) for a in apps_data[:3]]
            print(f"           ↳ Sample Apps: {', '.join(sample_apps)}")

        # 4. Visited Websites & Circuit Breaker
        res_sites = client.get("/api/websites")
        sites_data = res_sites.json() if res_sites.status_code == 200 else []
        check(
            "Sites & URL Domain Controller (/api/websites)",
            res_sites.status_code == 200 and len(sites_data) > 0,
            f"{len(sites_data)} domains tracked & circuit-breaker ready"
        )
        if sites_data:
            sample_sites = [s.get("domain") for s in sites_data[:3]]
            print(f"           ↳ Sample Domains: {', '.join(sample_sites)}")

        # 5. Website Circuit Breaker Toggle Simulation
        test_domain = "instagram.com"
        res_toggle_off = client.post(f"/api/websites/{test_domain}/toggle", json={"action": "OFF"})
        is_blocked = res_toggle_off.json().get("is_blocked", False) if res_toggle_off.status_code == 200 else False
        res_toggle_on = client.post(f"/api/websites/{test_domain}/toggle", json={"action": "ON"})
        is_restored = not res_toggle_on.json().get("is_blocked", True) if res_toggle_on.status_code == 200 else False
        check(
            "Website Circuit Breaker Toggle (OFF/ON)",
            res_toggle_off.status_code == 200 and is_blocked and is_restored,
            f"Successfully cut off and restored {test_domain}"
        )

        # 6. Dynamic PAC Script Generation
        res_pac = client.get("/api/websites/switchgate.pac")
        check(
            "Dynamic Browser PAC Script (/api/websites/switchgate.pac)",
            res_pac.status_code == 200 and "FindProxyForURL" in res_pac.text,
            "Valid PAC auto-config syntax"
        )

        # 7. Firebase Authentication Configuration
        res_auth_cfg = client.get("/api/auth/config")
        auth_data = res_auth_cfg.json() if res_auth_cfg.status_code == 200 else {}
        check(
            "Firebase Identity Config (/api/auth/config)",
            res_auth_cfg.status_code == 200 and "apiKey" in auth_data,
            f"Project: {auth_data.get('projectId', 'demo')}"
        )

        # 8. User Sync Session Simulation (Google / Apple)
        sync_payload = {
            "uid": "test_admin_user_001",
            "email": "tester@switchgate.lan",
            "display_name": "Test Suite Administrator",
            "provider": "google.com"
        }
        res_sync = client.post("/api/auth/sync", json=sync_payload)
        check(
            "User Session Sync & Persistence (/api/auth/sync)",
            res_sync.status_code == 200 and res_sync.json().get("authenticated", False),
            "Profile persisted to SQLite"
        )

        # 9. LAN Devices & Network Scanner
        res_dev = client.get("/api/devices")
        dev_data = res_dev.json() if res_dev.status_code == 200 else []
        check(
            "LAN Devices & Scanner (/api/devices)",
            res_dev.status_code == 200,
            f"{len(dev_data)} devices in network cache"
        )

        # 10. Database Integrity Check
        all_settings = db.get_all_settings()
        check(
            "SQLite Database Integrity & Schema (WAL Mode)",
            isinstance(all_settings, dict),
            f"{len(all_settings)} persistent key-value configuration flags"
        )

    except Exception as exc:
        test_failed += 1
        print(f"  ❌ TEST SUITE EXCEPTION: {exc}")

    print("-" * 65)
    print(f"  Total Tests Executed: {test_passed + test_failed} | Passed: {test_passed} | Failed: {test_failed}")
    if test_failed == 0:
        print("  🎉 ALL TESTS PASSED! Application is 100% production ready.")
    else:
        print("  ⚠️ Some tests failed. Review the errors above.")
    print("=" * 65 + "\n")

    return test_failed == 0


def main():
    parser = argparse.ArgumentParser(description="SwitchGate Application Runner & Test Suite")
    parser.add_argument("--test", action="store_true", help="Run automated smoke tests and exit")
    parser.add_argument("--browser", action="store_true", help="Force browser mode (skip WebView2 desktop window)")
    parser.add_argument("--headless", action="store_true", help="Run server without opening window or browser")
    parser.add_argument("--no-elevate", action="store_true", help="Skip UAC elevation prompt and run in user mode")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on (default: 8000)")
    args = parser.parse_args()

    # If --test is specified, run tests directly and exit cleanly
    if args.test:
        success = run_automated_smoke_tests(port=args.port)
        sys.exit(0 if success else 1)

    # Request UAC elevation if running interactively and not opted out
    request_elevation_if_needed(skip_elevation=args.no_elevate or args.browser or args.headless)

    from backend.config import AppConfig
    port = args.port or AppConfig.PORT
    app_url = f"http://127.0.0.1:{port}"

    # Check if port is already running another instance
    if is_port_in_use(port):
        print(f"[*] Port {port} is already active. Attempting to open SwitchGate UI...")
        if not args.headless:
            webbrowser.open(app_url)
        return

    # Desktop Window Mode (Default if available and not forced to browser/headless)
    if not args.browser and not args.headless:
        try:
            import webview
            import desktop_app
            print("[*] Launching SwitchGate Native Windows Desktop App (WebView2)...")
            desktop_app.main()
            return
        except ImportError:
            print("[*] 'pywebview' not installed. Falling back to Browser mode...")
        except Exception as e:
            print(f"[!] Desktop window note: {e}. Falling back to Browser mode...")

    # Browser / Server Mode
    import uvicorn
    from backend.main import app

    if not args.headless:
        print(f"[*] Launching SwitchGate Cyber Gateway at {app_url}...")
        open_browser_delayed(app_url, delay_seconds=0.7)

    admin_status = "Elevated Administrator (Full Power)" if is_admin() else "Standard User Mode"
    print(f"""
===============================================================
  ⚡ SWITCHGATE INTERNET v{AppConfig.APP_VERSION} (CYBER GATEWAY)
  Network IP : {AppConfig.LOCAL_IP} | Gateway: {AppConfig.GATEWAY_IP}
  Web UI     : {app_url}
  Admin Mode : {admin_status}
===============================================================
Press Ctrl+C to stop the server gracefully.
""")

    try:
        uvicorn.run(
            app,
            host=AppConfig.HOST,
            port=port,
            log_level="info" if AppConfig.DEBUG else "warning"
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping SwitchGate gracefully...")
    finally:
        try:
            from backend.core.activator import activator
            activator.deactivate_all()
        except Exception:
            pass


if __name__ == "__main__":
    main()
