"""
SwitchGate - Real Apps, Live Websites & Fast Control Integration Test
"""
import sys
from pathlib import Path

# Ensure root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.main import app
from backend.core.app_controller import app_controller
from backend.core.url_controller import url_controller
from backend.database import db

def test_live():
    print("==================================================")
    print("   🧪 TESTING REAL APPS & WEBSITES CONTROLLER     ")
    print("==================================================")

    # 1. Test Real Running Windows Apps
    print("\n[1/3] Detecting Real Running Windows Apps with Open Sockets...")
    apps = app_controller.get_real_active_apps()
    print(f"      Found {len(apps)} real active networked applications on this PC:")
    for a in apps[:6]:
        print(f"      - {a['friendly_name']} ({a['name']}) | Sockets: {a['connections_count']} | KB/s: {a['current_kbps']}")
    assert len(apps) > 0, "Expected at least 1 running networked process"

    # Test App Internet Toggle (ON/OFF)
    test_app = apps[0]
    app_name = test_app['name']
    exe_path = test_app.get('exe_path', '')
    print(f"\n      Testing ON/OFF internet switch on app: {app_name}...")
    
    # Toggle OFF
    app_controller.toggle_app_internet(app_name, exe_path, "OFF")
    assert app_name.lower() in app_controller.blocked_apps
    print(f"      [OK] App {app_name} internet switched OFF (Process remains running safely).")

    # Toggle ON
    app_controller.toggle_app_internet(app_name, exe_path, "ON")
    assert app_name.lower() not in app_controller.blocked_apps
    print(f"      [OK] App {app_name} internet switched ON (Access restored).")

    # 2. Test Real Live Visited Websites & Domain Controller
    print("\n[2/3] Testing Live Visited Websites & Domain Controller...")
    websites = url_controller.get_live_websites()
    print(f"      Tracked {len(websites)} live website domains:")
    for w in websites[:5]:
        print(f"      - {w['friendly_name']} ({w['domain']}) | Category: {w['category']} | Blocked: {w['is_blocked']}")
    assert len(websites) > 0, "Expected live website domains list"

    # Test Website Toggle (ON/OFF)
    test_domain = "instagram.com"
    print(f"\n      Testing instant ON/OFF switch on domain: {test_domain}...")
    url_controller.toggle_website(test_domain, "OFF")
    assert db.is_domain_blocked(test_domain) is True
    print(f"      [OK] Website {test_domain} switched OFF (Blocked across all browsers).")

    url_controller.toggle_website(test_domain, "ON")
    assert db.is_domain_blocked(test_domain) is False
    print(f"      [OK] Website {test_domain} switched ON (Restored).")

    # 3. FastAPI App Router Verification
    print("\n[3/3] Checking API Routers...")
    routes = [r.path for r in app.routes]
    assert "/api/apps" in routes
    assert "/api/websites" in routes
    assert "/api/devices" in routes
    print(f"      [OK] All REST endpoints and WebSockets registered ({len(routes)} routes).")

    print("\n==================================================")
    print("   🎉 ALL REAL-TIME SYSTEM ENGINE TESTS PASSED!   ")
    print("==================================================")

if __name__ == "__main__":
    test_live()
