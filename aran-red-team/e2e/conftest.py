"""
Aran E2E WAF Test Suite — conftest.py

Tests fire live requests through the full stack:
  Client → Envoy :8443 (jwt_authn) → SCG :8080 (RaspPolicyRoutingFilter) → Upstream

Requires the full docker-compose stack to be running.
Run with:
  docker-compose -f aran-backend/docker-compose.yml up -d
  pytest aran-red-team/e2e/ -v

Environment variables:
  ARAN_WAF_URL   — Envoy edge (default http://localhost:8443)
  ARAN_SCG_URL   — SCG direct (default http://localhost:8080)  [used for bypass tests]
"""

import os
import time
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import base64
import json
import struct

WAF_URL = os.environ.get("ARAN_WAF_URL", "http://localhost:11004")
SCG_URL = os.environ.get("ARAN_SCG_URL", "http://localhost:11003")


# ── RASP mask constants (must match RaspThreatBit.java) ──────────────────────
class Mask:
    CLEAN            = 0x0000
    ROOT             = 0x0001
    FRIDA            = 0x0002
    DEBUGGER         = 0x0004
    HOOKED           = 0x0010
    TAMPERED         = 0x0020
    UNTRUSTED_INST   = 0x0040
    ENV_TAMPERING    = 0x0200
    RUNTIME_INTEGRITY= 0x0400
    PROXY            = 0x0800
    ZYGISK           = 0x1000
    ANON_ELF         = 0x2000
    ZYGISK_FD        = 0x4000
    SCREEN_RECORDING = 0x010000   # Kotlin-layer bit
    OVERLAY          = 0x020000
    KEYLOGGER        = 0x040000

    CRITICAL = ROOT | FRIDA | ZYGISK | ANON_ELF | ZYGISK_FD
    TAMPER   = TAMPERED | UNTRUSTED_INST | RUNTIME_INTEGRITY | ENV_TAMPERING
    UI       = SCREEN_RECORDING | OVERLAY | KEYLOGGER
    NETWORK  = PROXY


@pytest.fixture(scope="session")
def ec_key_pair():
    """Generate a fresh P-256 key pair for this test session."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="session")
def attacker_key_pair():
    """Separate key pair NOT registered with the JWKS endpoint."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture(scope="session", autouse=True)
def register_key_with_jwks(ec_key_pair):
    """
    Register the test EC public key with aran-iam-service via the device
    registration endpoint so Envoy's JWKS cache can pick it up.

    In a full integration run this would POST to /api/v1/auth/device/register.
    For now we skip if the endpoint doesn't exist (unit-level Envoy tests use
    a pre-seeded key via ARAN_SIGIL_EC_PUBLIC_KEY_B64 env var in SCG).
    """
    import requests
    _, pub = ec_key_pair
    pub_der_b64 = base64.b64encode(
        pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    try:
        requests.post(
            f"{SCG_URL.replace('8080', '8081')}/api/v1/auth/device/register",
            json={"key_id": "test-device-key", "app_id": "org.mazhai.aran.e2e", "public_key_b64": pub_der_b64},
            timeout=3
        )
    except Exception as e:
        print(f"Failed to register key with JWKS: {e}")
        pass   # endpoint may not exist yet; Envoy direct tests will use static key


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _der_sig_to_raw(der_sig: bytes) -> bytes:
    """Convert DER-encoded ECDSA signature to raw R||S (64 bytes for P-256)."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def make_sigil(private_key, mask: int, device_id: str = None, app_id: str = None,
               issued_offset_sec: int = 0, ttl_sec: int = 300,
               issuer: str = "aran-sdk", audience: str = "aran-waf", kid: str = None) -> str:
    """
    Build a minimal ES256 JWT Sigil matching what AranSigilEngine produces.

    issued_offset_sec: negative = issued in the past (for expiry tests)
    ttl_sec: set to 0 or negative to produce an already-expired token
    kid: key ID for JWKS matching (default: "test-device-key")
    """
    now = int(time.time()) + issued_offset_sec
    header = {"alg": "ES256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": device_id or ("test-device-" + uuid.uuid4().hex[:8]),
        "app": app_id or "org.mazhai.aran.e2e",
        "src": "NATIVE",
        "mask": mask,
        "iat": now,
        "exp": now + ttl_sec,
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    raw_sig = _der_sig_to_raw(der_sig)
    s = _b64url(raw_sig)
    return f"{h}.{p}.{s}"


@pytest.fixture
def waf_url():
    return WAF_URL


@pytest.fixture
def scg_url():
    return SCG_URL
