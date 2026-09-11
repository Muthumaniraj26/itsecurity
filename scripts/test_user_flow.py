import httpx
import sys

def test_user_flow():
    base = 'http://localhost:8000/api/user'
    print("Testing User Store & Persistence Flow...")

    # 1. Register or Login
    reg = httpx.post(f'{base}/register', json={'name': 'Enterprise SecOps', 'email': 'secops_test@company.com', 'password': 'SecOpsSecurePass2026!'})
    if reg.status_code == 409:
        log = httpx.post(f'{base}/login', json={'email': 'secops_test@company.com', 'password': 'SecOpsSecurePass2026!'})
        assert log.status_code == 200, f"Login failed: {log.text}"
        token = log.json()['token']
        print("[OK] Logged in existing user")
    else:
        assert reg.status_code == 200, f"Register failed: {reg.text}"
        token = reg.json()['token']
        print("[OK] Registered new user")

    headers = {'Authorization': f'Bearer {token}'}

    # 2. Get me
    me = httpx.get(f'{base}/me', headers=headers)
    assert me.status_code == 200, f"Get me failed: {me.text}"
    user_info = me.json()['user']
    print(f"[OK] Profile retrieved: {user_info['name']} ({user_info['email']})")

    # 3. Complete onboarding
    onb = httpx.post(f'{base}/onboarding/complete', headers=headers)
    assert onb.status_code == 200, f"Onboarding complete failed: {onb.text}"
    print(f"[OK] Onboarding marked complete: {onb.json()}")

    # 4. Record history
    hist = httpx.post(f'{base}/history', json={
        'tool': 'URL Phishing Sandbox',
        'target': 'https://verify-account-portal.xyz',
        'riskLevel': 'CRITICAL',
        'confidence': 94,
        'summary': 'Phishing trap identified targeting enterprise single-sign-on credentials.',
        'resultJson': {'heuristicScore': 94, 'status': 'MALICIOUS'}
    }, headers=headers)
    assert hist.status_code == 200, f"History record failed: {hist.text}"
    print(f"[OK] History record inserted: ID {hist.json().get('id')}")

    # 5. Fetch history
    h_list = httpx.get(f'{base}/history', headers=headers)
    assert h_list.status_code == 200, f"History list failed: {h_list.text}"
    history_items = h_list.json()
    print(f"[OK] History records retrieved: {len(history_items)} items")

    # 6. Save Report
    rep = httpx.post(f'{base}/reports', json={
        'reportName': 'Critical Incident Report: verify-account-portal.xyz',
        'target': 'https://verify-account-portal.xyz',
        'riskLevel': 'CRITICAL',
        'contentJson': {'advisory': 'Immediate DNS block recommended'}
    }, headers=headers)
    assert rep.status_code == 200, f"Save report failed: {rep.text}"
    report_id = rep.json().get('id')
    print(f"[OK] Report saved: ID {report_id}")

    # 7. Fetch Reports
    r_list = httpx.get(f'{base}/reports', headers=headers)
    assert r_list.status_code == 200, f"Fetch reports failed: {r_list.text}"
    reports = r_list.json()
    print(f"[OK] Reports retrieved: {len(reports)} reports")

    # 8. Fetch Notifications
    notifs = httpx.get(f'{base}/notifications', headers=headers)
    assert notifs.status_code == 200, f"Fetch notifications failed: {notifs.text}"
    notif_list = notifs.json()
    print(f"[OK] Notifications retrieved: {len(notif_list)} notifications")

    # 9. Delete report test
    if report_id:
        del_rep = httpx.delete(f'{base}/reports/{report_id}', headers=headers)
        assert del_rep.status_code == 200, f"Delete report failed: {del_rep.text}"
        print(f"[OK] Deleted report: ID {report_id}")

    print("\n==================================================")
    print("   ALL USER STORE & PERSISTENCE TESTS PASSED [OK]")
    print("==================================================")

if __name__ == '__main__':
    test_user_flow()
