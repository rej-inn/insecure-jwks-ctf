from flask import Flask, request, jsonify
import requests
import jwt
from jwt import algorithms

app = Flask(__name__)

# ============================================================
# 🚩 CTF FLAG
# Returned only when role == admin
# ============================================================
FLAG = "FLAG{jwks_trust_is_security}"

# ============================================================
# ❌ INTENTIONAL MISCONFIGURATION (FOR CTF)
# The app trusts MULTIPLE JWKS sources.
# Internal JWKS should NEVER be trusted in real life.
# ============================================================
JWKS_URLS = [
    "http://localhost:5001/jwks.json",              # Public / rotating
    "http://localhost:5001/internal/jwks.json"     # ❌ Internal (weak key)
]

JWKS_CACHE = None


# ============================================================
# Fetch JWKS once and cache forever (stale trust)
# ============================================================
def fetch_jwks():
    global JWKS_CACHE

    if JWKS_CACHE is None:
        JWKS_CACHE = []

        for url in JWKS_URLS:
            try:
                resp = requests.get(url, timeout=2)
                data = resp.json()
                keys = data.get("keys", [])
                JWKS_CACHE.extend(keys)
            except Exception:
                # ❌ Fail silently
                pass

    return JWKS_CACHE


# ============================================================
# Resolve public key by kid (blind trust)
# ============================================================
def get_public_key_for_kid(kid):
    jwks = fetch_jwks()

    for jwk in jwks:
        if jwk.get("kid") == kid:
            return algorithms.RSAAlgorithm.from_jwk(jwk)

    raise Exception("Unknown kid")


# ============================================================
# Verify JWT
# ============================================================
@app.route("/verify")
def verify():
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth.split(" ", 1)[1]

    try:
        # Extract kid without verification
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        if not kid:
            return jsonify({"error": "Missing kid"}), 400

        public_key = get_public_key_for_kid(kid)

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )

        # ====================================================
        # 🚩 FLAG LOGIC
        # ====================================================
        if payload.get("role") == "admin":
            return jsonify({
                "user": payload.get("user"),
                "role": payload.get("role"),
                "flag": FLAG
            })

        return jsonify(payload)

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================
# Start server
# ============================================================
if __name__ == "__main__":
    app.run(port=5002)
