import urllib.request
import json

def test():
    # 1. Test GET /api/employees
    req = urllib.request.Request('http://localhost:8000/api/employees')
    with urllib.request.urlopen(req) as resp:
        employees = json.loads(resp.read().decode('utf-8'))
        print(f"[OK] Found {len(employees)} employees in SQL")
        for e in employees[:3]:
            print(f"   - {e['id']}: {e['name']} | Phone: {e.get('phone')} | Role: {e['role']}")

    # 2. Test 2FA Initiate Login
    payload = json.dumps({'emp_id': 'E-101', 'password': 'password123'}).encode('utf-8')
    req = urllib.request.Request('http://localhost:8000/api/auth/initiate-login', data=payload, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        init_res = json.loads(resp.read().decode('utf-8'))
        print(f"[OK] 2FA Initiate: status={init_res.get('status')} preview_otp={init_res.get('auth_code_preview')} phone={init_res.get('masked_phone')}")
        otp = init_res.get('auth_code_preview')

    # 3. Test 2FA Verify OTP
    payload2 = json.dumps({'emp_id': 'E-101', 'auth_code': otp}).encode('utf-8')
    req2 = urllib.request.Request('http://localhost:8000/api/auth/verify-mobile-auth', data=payload2, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req2) as resp:
        verify_res = json.loads(resp.read().decode('utf-8'))
        print(f"[OK] 2FA Verify: Logged in as {verify_res['employee']['name']}, Token={verify_res.get('token')}")
        print(f"     Modules accessible: {verify_res.get('permissions')}")

    # 4. Test Reset Password (by Admin E-105)
    payload3 = json.dumps({'new_password': 'UpdatedPass999', 'admin_id': 'E-105'}).encode('utf-8')
    req3 = urllib.request.Request('http://localhost:8000/api/employees/E-102/reset-password', data=payload3, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req3) as resp:
        reset_res = json.loads(resp.read().decode('utf-8'))
        print(f"[OK] Admin Password Reset: {reset_res.get('message')}")

    # 5. Verify Static UI serves index.html
    req4 = urllib.request.Request('http://localhost:8000/')
    with urllib.request.urlopen(req4) as resp:
        content = resp.read().decode('utf-8')
        print(f"[OK] Index.html served: length={len(content)} bytes")

if __name__ == '__main__':
    test()
