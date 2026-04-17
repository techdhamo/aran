"""
Aran E2E WAF Test Suite — SCG RaspPolicyRoutingFilter

These tests send valid Sigils with varying mask values and verify that the
SCG RaspPolicyRoutingFilter makes the correct routing decision.

Scenarios:
  P1  — clean mask (0x0) → X-Aran-Policy: CLEAN, upstream 2xx
  P2  — critical mask (ROOT) → 403 CRITICAL_THREAT in response body
  P3  — critical mask (FRIDA) → 403 CRITICAL_THREAT
  P4  — critical mask (ZYGISK | ANON_ELF) → 403 CRITICAL_THREAT
  P5  — tamper mask (TAMPERED | UNTRUSTED_INST) → 403 APK_INTEGRITY
  P6  — UI mask (OVERLAY) → 302 redirect to /step-up/biometric
  P7  — UI mask (SCREEN_RECORDING) → 302 redirect to /step-up/biometric
  P8  — network mask (PROXY) → request rewritten to /sandbox path
  P9  — combination CRITICAL + NETWORK → CRITICAL wins (most severe first)
  P10 — missing X-Aran-Rasp-Mask (SCG received without going through Envoy) → 401

Note: These tests call SCG DIRECTLY (bypass Envoy) to isolate SCG filter logic.
      They inject X-Aran-Rasp-Mask manually as Envoy's Lua filter would.
"""

import pytest
import requests
from conftest import make_sigil, Mask


TARGET = "/api/v1/tenant/status"


def _headers(mask: int, device: str = "test-device") -> dict:
    """Simulate Envoy's injected headers reaching SCG."""
    return {
        "X-Aran-Rasp-Mask": str(mask),
        "X-Aran-Device-Id": device,
        "X-Aran-App-Id": "org.mazhai.aran.e2e",
    }


def test_P1_clean_mask_clean_policy(scg_url):
    r = requests.get(f"{scg_url}{TARGET}", headers=_headers(Mask.CLEAN), timeout=5)
    assert r.status_code not in (403, 401), f"Clean mask blocked: {r.status_code}"
    # SCG annotates the upstream request — verify policy header appears in response
    # (only visible if upstream echoes it, otherwise verify by absence of 403)


def test_P2_root_detected_critical_block(scg_url):
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(Mask.ROOT), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403, f"ROOT mask not blocked: {r.status_code}"
    body = r.json()
    assert body.get("audit_code") == "CRITICAL_THREAT", f"Wrong audit code: {body}"


def test_P3_frida_detected_critical_block(scg_url):
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(Mask.FRIDA), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403
    assert r.json().get("audit_code") == "CRITICAL_THREAT"


def test_P4_zygisk_and_anon_elf_critical_block(scg_url):
    mask = Mask.ZYGISK | Mask.ANON_ELF
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(mask), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403
    assert r.json().get("audit_code") == "CRITICAL_THREAT"


def test_P5_apk_integrity_block(scg_url):
    mask = Mask.TAMPERED | Mask.UNTRUSTED_INST
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(mask), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403, f"Tamper mask not blocked: {r.status_code}"
    assert r.json().get("audit_code") == "APK_INTEGRITY", f"Wrong audit code: {r.json()}"


def test_P6_overlay_detected_step_up_redirect(scg_url):
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(Mask.OVERLAY), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 302, f"Overlay mask should redirect to step-up: {r.status_code}"
    location = r.headers.get("Location", "")
    assert "/step-up/biometric" in location, (
        f"Redirect location wrong: {location}"
    )
    assert "UI_COMPROMISE" in location or r.headers.get("X-Aran-Audit-Code") == "UI_COMPROMISE"


def test_P7_screen_recording_step_up_redirect(scg_url):
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(Mask.SCREEN_RECORDING), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 302
    assert "/step-up/biometric" in r.headers.get("Location", "")


def test_P8_proxy_network_sandbox_rewrite(scg_url):
    """PROXY flag → request rewritten to /sandbox/api/v1/... route."""
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(Mask.PROXY), timeout=5,
                     allow_redirects=False)
    # SCG rewrites internally; upstream may 404 on /sandbox/... path
    # but must NOT return 403 CRITICAL_THREAT or 401.
    assert r.status_code not in (401, 403), (
        f"PROXY mask incorrectly hard-blocked: {r.status_code} — should sandbox-route"
    )


def test_P9_critical_wins_over_network(scg_url):
    """When both CRITICAL and NETWORK bits are set, CRITICAL policy takes precedence."""
    mask = Mask.FRIDA | Mask.PROXY
    r = requests.get(f"{scg_url}{TARGET}",
                     headers=_headers(mask), timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403
    assert r.json().get("audit_code") == "CRITICAL_THREAT"


def test_P10_missing_mask_header(scg_url):
    """Request reaching SCG with no X-Aran-Rasp-Mask (no Envoy in path) → 401."""
    r = requests.get(f"{scg_url}{TARGET}", timeout=5)
    assert r.status_code == 401, (
        f"Request with no mask header should be rejected as MISSING_SIGIL: {r.status_code}"
    )


def test_P11_full_stack_clean(waf_url, ec_key_pair):
    """
    Full-stack: Client → Envoy → SCG → Upstream
    Valid Sigil with clean mask traverses entire pipeline unblocked.
    Verify X-Aran-Gateway response header confirming request passed through SCG.
    """
    priv, _ = ec_key_pair
    token = make_sigil(priv, Mask.CLEAN)
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5)
    # X-Aran-Gateway is added by SCG default-filters — its presence proves
    # the request passed through Envoy AND SCG (not just one of them)
    assert "X-Aran-Gateway" in r.headers, (
        "X-Aran-Gateway not in response — request may not have traversed SCG"
    )
    assert r.status_code not in (401, 403), f"Clean full-stack request blocked: {r.status_code}"


def test_P12_full_stack_critical_blocked(waf_url, ec_key_pair):
    """
    Full-stack: Valid Sigil with CRITICAL mask.
    Envoy accepts the valid JWT; SCG blocks at policy layer with 403.
    """
    priv, _ = ec_key_pair
    token = make_sigil(priv, Mask.CRITICAL)
    r = requests.get(f"{waf_url}{TARGET}",
                     headers={"X-Aran-Sigil": token}, timeout=5,
                     allow_redirects=False)
    assert r.status_code == 403, (
        f"SECURITY FAIL: CRITICAL mask passed through SCG unchallenged: {r.status_code}"
    )
    assert r.json().get("audit_code") == "CRITICAL_THREAT"
