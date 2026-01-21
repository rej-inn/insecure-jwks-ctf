from flask import Flask, jsonify
import time
import base64
import os
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# ============================================================
# Configuration
# ============================================================
ROTATION_INTERVAL = 30  # seconds

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "..", "keys")

WEAK_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "small_rsa.pem")


# ============================================================
# Helper: Load RSA public key and convert to JWK
# ============================================================
def load_public_key(filename, kid):
    path = os.path.join(KEYS_DIR, filename)

    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
        numbers = key.public_numbers()

        def b64(x):
            return base64.urlsafe_b64encode(
                x.to_bytes((x.bit_length() + 7) // 8, "big")
            ).decode().rstrip("=")

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": b64(numbers.n),
            "e": b64(numbers.e),
        }


# ============================================================
# Keys
# ============================================================
ROTATING_KEYS = [
    load_public_key("strong_rsa_1.pub", "strong-key-1"),
    load_public_key("strong_rsa_2.pub", "strong-key-2"),
]

WEAK_PUBLIC_KEY = load_public_key("small_rsa.pub", "internal-weak-key")


# ============================================================
# Routes
# ============================================================

@app.route("/")
def index():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Enterprise Service Console</title>
<style>
    body {
        margin: 0;
        font-family: system-ui, -apple-system, BlinkMacSystemFont,
                     "Segoe UI", Roboto, Ubuntu, sans-serif;
        background: linear-gradient(135deg, #0b1220, #111827);
        color: #e5e7eb;
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .panel {
        width: 520px;
        background: #020617;
        border-radius: 16px;
        padding: 36px 42px;
        box-shadow: 0 30px 60px rgba(0,0,0,0.7);
    }

    .header {
        display: flex;
        align-items: center;
        margin-bottom: 28px;
    }

    .logo {
        width: 44px;
        height: 44px;
        border-radius: 10px;
        background: linear-gradient(135deg, #2563eb, #1e40af);
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 18px;
        margin-right: 14px;
        color: #fff;
    }

    h1 {
        font-size: 20px;
        font-weight: 600;
        margin: 0;
    }

    p {
        font-size: 14px;
        line-height: 1.6;
        color: #9ca3af;
        margin-bottom: 26px;
    }

    .status-box {
        display: flex;
        justify-content: space-between;
        padding: 14px 18px;
        background: #020617;
        border: 1px solid #1e293b;
        border-radius: 10px;
        margin-bottom: 26px;
        font-size: 14px;
    }

    .status-ok {
        color: #22c55e;
        font-weight: 600;
    }

    .meta {
        font-size: 12px;
        color: #6b7280;
        border-top: 1px solid #1e293b;
        padding-top: 14px;
        display: flex;
        justify-content: space-between;
    }
</style>
</head>
<body>

<div class="panel">
    <div class="header">
        <div class="logo">ES</div>
        <h1>Enterprise Service Console</h1>
    </div>

    <p>
        This console provides operational visibility for internal
        platform components and shared infrastructure services.
    </p>

    <div class="status-box">
        <span>System Health</span>
        <span class="status-ok">Operational</span>
    </div>

    <div class="meta">
        <span>Region: Global</span>
        <span>Build: 2026.01</span>
    </div>
</div>

</body>
</html>
"""


@app.route("/jwks.json")
def jwks():
    idx = int(time.time() / ROTATION_INTERVAL) % len(ROTATING_KEYS)
    return jsonify({"keys": [ROTATING_KEYS[idx]]})


@app.route("/internal/jwks.json")
def internal_jwks():
    return jsonify({"keys": [WEAK_PUBLIC_KEY]})


@app.route("/internal/debug")
def internal_debug():
    with open(WEAK_PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()

    return jsonify({
        "warning": "INTERNAL DEBUG ENDPOINT — DO NOT EXPOSE",
        "kid": "internal-weak-key",
        "private_key": private_key
    })


# ============================================================
# Start server
# ============================================================
if __name__ == "__main__":
    app.run(port=5001)
