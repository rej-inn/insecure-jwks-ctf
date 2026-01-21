import sys
import jwt

if len(sys.argv) != 2:
    print("Usage: python3 check_admin.py <JWT>")
    sys.exit(1)

token = sys.argv[1]

payload = jwt.decode(token, options={"verify_signature": False})

if payload.get("role") == "admin":
    print("[+] Admin access granted!")
else:
    print("[-] Token is valid but not admin")
