# Insecure JWKS Rotation CTF

## Objective
Exploit JWKS rotation + caching misconfiguration to forge a valid admin JWT.

## Vulnerabilities
- JWKS rotates but application caches keys forever
- Blind `kid` trust
- Weak RSA key exposed internally
- No key size enforcement

## Services
- JWKS Server: http://localhost:5001/jwks.json
- Internal JWKS: http://localhost:5001/internal/jwks.json
- Vulnerable API: http://localhost:5002/verify

## Goal
Create a JWT with:
{
  "role": "admin"
}
that is accepted by the `/verify` endpoint.
