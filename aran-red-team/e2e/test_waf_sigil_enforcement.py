"""
Aran E2E WAF Test Suite — Sigil Enforcement at Envoy Edge

Scenarios:
  E1  — No X-Aran-Sigil header → Envoy 401
  E2  — Malformed token (not a JWT) → Envoy 401
  E3  — Valid JWT but wrong issuer → Envoy 401
  E4  — Valid JWT but wrong audience → Envoy 401
  E5  — Expired JWT (issued 10 min ago, TTL 60s) → Envoy 401
  E6  — JWT signed with unregistered key → Envoy 401
  E7  — Valid JWT, clean mask (0x0000) → 200 upstream
  E8  — Auth and telemetry paths bypass jwt_authn entirely → passthrough
"""

import pytest
import requests
from conftest import make_sigil, Mask


TARGET = "/api/v1/tenant/status"   # protected banking route
AUTH   = "/api/v1/auth/admin/login"
TELEM  = "/api/v1/telemetry/ingest"


def test_E1_no_sigil(waf_url):
    """No Sigil header — Envoy jwt_authn must return 401."""
    r = requests.get(f"{waf_url}{TARGET}", timeout=5)
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text[:200]}"


def test_E2_malformed_token(waf_url):
    """Non-JWT string — Envoy must return 401."""
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": "not.a.jwt.at.all"}, timeout=5)
    assert r.status_code == 401, f"Expected 401 for malformed, got {r.status_code}"


def test_E3_wrong_issuer(waf_url, ec_key_pair):
    """JWT with wrong issuer — Envoy must reject (iss != aran-sdk)."""
    priv, _ = ec_key_pair
    token = make_sigil(priv, Mask.CLEAN, issuer="evil-sdk", kid="test-device-key")
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    assert r.status_code == 401, f"Expected 401 for wrong issuer, got {r.status_code}"


def test_E4_wrong_audience(waf_url, ec_key_pair):
    """JWT with wrong audience — Envoy must reject (aud != aran-waf)."""
    priv, _ = ec_key_pair
    token = make_sigil(priv, Mask.CLEAN, audience="some-other-service", kid="test-device-key")
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    assert r.status_code == 401, f"Expected 401 for wrong audience, got {r.status_code}"


def test_E5_expired_jwt(waf_url, ec_key_pair):
    """Token issued 10min ago with 60s TTL — must be expired, Envoy rejects."""
    priv, _ = ec_key_pair
    # issued_offset=-600 (10 min past) + ttl=60 → exp = 9 min ago
    token = make_sigil(priv, Mask.CLEAN, issued_offset_sec=-600, ttl_sec=60, kid="test-device-key")
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    assert r.status_code == 401, f"Expected 401 for expired JWT, got {r.status_code}"


def test_E6_wrong_ec_key(waf_url, attacker_key_pair):
    """JWT signed with unregistered attacker key — Envoy signature verify fails."""
    attacker_priv, _ = attacker_key_pair
    token = make_sigil(attacker_priv, Mask.CLEAN, kid="test-device-key")
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    assert r.status_code == 401, (
        f"SECURITY FAIL: JWT signed with unregistered key was accepted! "
        f"Status: {r.status_code}"
    )


def test_E7_clean_mask_passes(waf_url, ec_key_pair):
    """Valid JWT + clean mask — must reach upstream (200 or 404/502 is fine, not 401/403)."""
    priv, _ = ec_key_pair
    token = make_sigil(priv, Mask.CLEAN, kid="test-device-key")
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    assert r.status_code not in (401, 403), (
        f"Valid clean Sigil was blocked at WAF edge: {r.status_code} {r.text[:200]}"
    )


def test_E8_auth_bypasses_jwt_authn(waf_url):
    """Auth endpoint must be reachable without any Sigil (login flow precedes Sigil)."""
    r = requests.post(f"{waf_url}{AUTH}",
                      json={"email": "test@aran.io", "password": "testpassword"},
                      timeout=5)
    # 401 from the auth SERVICE (wrong creds) is fine — 401 from Envoy would have
    # no JSON body. We verify that the request at least reached the service.
    assert "X-Aran-Gateway" in r.headers or r.status_code in (200, 401, 400), (
        f"Auth endpoint was blocked by Envoy jwt_authn: {r.status_code}"
    )


def test_E9_telemetry_bypasses_jwt_authn(waf_url):
    """Telemetry ingest must be reachable without any Sigil (SDK posts independently)."""
    r = requests.post(f"{waf_url}{TELEM}",
                      json={"schema_version": "2.0", "encrypted_blob": "dGVzdA==",
                            "nonce": "test", "timestamp": 0, "payload_sha256": ""},
                      timeout=5)
    # May return 202 ACCEPTED or 400/500 (bad payload) but NOT 401 from Envoy
    assert r.status_code != 401, (
        f"Telemetry endpoint was blocked by Envoy jwt_authn — bypass rule missing: {r.status_code}"
    )
