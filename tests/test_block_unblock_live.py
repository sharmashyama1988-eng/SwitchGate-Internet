"""
Live test for Website & App blocking and unblocking (Zero-Npcap Native Windows).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from backend.main import app
from backend.core.url_controller import url_controller

client = TestClient(app)

print('==================================================')
print('   🧪 TESTING WEBSITE (URL) BLOCK / UNBLOCK')
print('==================================================')

# 1. Block instagram.com
res1 = client.post('/api/websites/instagram.com/toggle', json={'action': 'OFF'})
print('[1] Block instagram.com ->', res1.status_code, res1.json().get('message'))
assert res1.status_code == 200
assert res1.json()['is_blocked'] is True

# 2. Check PAC script
pac_res = client.get('/api/websites/switchgate.pac')
print(f'[2] PAC Script has instagram.com: {"instagram.com" in pac_res.text}')
assert "instagram.com" in pac_res.text

# 3. Verify in Website List
sites = client.get('/api/websites').json()
insta = next((s for s in sites if s['domain'] == 'instagram.com'), None)
print(f'[3] instagram.com in API is_blocked: {insta.get("is_blocked") if insta else False}')
assert insta is not None
assert insta['is_blocked'] is True

# 4. Unblock instagram.com
res2 = client.post('/api/websites/instagram.com/toggle', json={'action': 'ON'})
print('[4] Unblock instagram.com ->', res2.status_code, res2.json().get('message'))
assert res2.status_code == 200
assert res2.json()['is_blocked'] is False

# 5. Check PAC script restored
pac_res2 = client.get('/api/websites/switchgate.pac')
is_direct = 'DIRECT' in pac_res2.text and 'instagram.com' not in pac_res2.text
print(f'[5] PAC Script restored to DIRECT: {is_direct}')
assert is_direct

print('\n==================================================')
print('   🧪 TESTING APP INTERNET BLOCK / UNBLOCK')
print('==================================================')

# 1. Block chrome.exe
res_app_off = client.post('/api/apps/chrome.exe/toggle', json={'action': 'OFF', 'exe_path': ''})
print('[1] Block chrome.exe ->', res_app_off.status_code, res_app_off.json().get('message'))
assert res_app_off.status_code == 200
assert res_app_off.json()['is_blocked'] is True

# 2. Verify in app list
apps_list = client.get('/api/apps').json()
chrome_app = next((a for a in apps_list if a['name'].lower() == 'chrome.exe'), None)
is_blocked = chrome_app.get('is_blocked') if chrome_app else False
print(f'[2] chrome.exe is_blocked in API: {is_blocked}')
assert is_blocked is True

# 3. Unblock chrome.exe
res_app_on = client.post('/api/apps/chrome.exe/toggle', json={'action': 'ON', 'exe_path': ''})
print('[3] Unblock chrome.exe ->', res_app_on.status_code, res_app_on.json().get('message'))
assert res_app_on.status_code == 200
assert res_app_on.json()['is_blocked'] is False

# 4. Verify restored in app list
apps_list2 = client.get('/api/apps').json()
chrome_app2 = next((a for a in apps_list2 if a['name'].lower() == 'chrome.exe'), None)
is_blocked2 = chrome_app2.get('is_blocked') if chrome_app2 else False
print(f'[4] chrome.exe is_blocked in API: {is_blocked2}')
assert is_blocked2 is False

print('\n==================================================')
print('   🎉 ALL URL & APP BLOCK/UNBLOCK TESTS PASSED!')
print('==================================================')
