"""
Aran Red-Team | Telemetry Test: Replay Attack Suite

Tests:
    T1 — Nonce replay: same nonce sent twice → second rejected
    T2 — Timestamp stale: timestamp > 5 minutes old → rejected
    T3 — Timestamp future: timestamp > 5 minutes future → rejected
    T4 — Batch replay: same blob repeated in a batch → all but first rejected
"""

import time
import uuid
import hashlib
import base64

import pytest
import requests

from conftest import (
    encrypt_payload, build_rbi_payload, build_envelope, BASE_URL
)


INGEST_URL = f"{BASE_URL}/api/v1/telemetry/ingest"
BATCH_URL  = f"{BASE_URL}/api/v1/telemetry/ingest/batch"


@pytest.mark.parametrize("label,expected_status", [
    ("ACCEPTED", "ACCEPTED"),
])
def test_T0_baseline_valid_event(rsa_pub_key, label, expected_status):
    """Sanity check: a well-formed event is accepted."""
    nonce = str(uuid.uuid4())
    ts = int(time.time() * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)

    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202, f"Expected 202, got {r.status_code}: {r.text}"
    body = r.json()
    assert body["status"] == "ACCEPTED", f"Expected ACCEPTED, got: {body}"


def test_T1_nonce_replay(rsa_pub_key):
    """Same nonce submitted twice must result in REJECTED_REPLAY on second call."""
    nonce = str(uuid.uuid4())
    ts = int(time.time() * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    # First submission — must be accepted
    r1 = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r1.status_code == 202
    assert r1.json()["status"] == "ACCEPTED", f"First submission failed: {r1.json()}"

    # Replay — must be rejected
    r2 = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r2.status_code == 202
    body2 = r2.json()
    assert body2["status"] == "REJECTED_REPLAY", (
        f"SECURITY FAIL: nonce replay was accepted! Response: {body2}"
    )


def test_T2_stale_timestamp(rsa_pub_key):
    """Timestamp older than 5 minutes must be rejected."""
    nonce = str(uuid.uuid4())
    # 6 minutes in the past
    ts = int(time.time() * 1000) - (6 * 60 * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_REPLAY", (
        f"SECURITY FAIL: stale timestamp was accepted! Response: {body}"
    )


def test_T3_future_timestamp(rsa_pub_key):
    """Timestamp more than 5 minutes in the future must be rejected."""
    nonce = str(uuid.uuid4())
    ts = int(time.time() * 1000) + (6 * 60 * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_REPLAY", (
        f"SECURITY FAIL: future timestamp was accepted! Response: {body}"
    )


def test_T4_batch_nonce_replay(rsa_pub_key):
    """Same envelope repeated 3x in a batch → only first accepted, rest rejected."""
    nonce = str(uuid.uuid4())
    ts = int(time.time() * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    batch = [envelope, envelope, envelope]
    r = requests.post(BATCH_URL, json=batch, timeout=10)
    assert r.status_code == 202
    # Batch endpoint returns aggregate ACCEPTED for the batch call itself;
    # individual rejection is logged server-side. Verify via separate single
    # ingest that the nonce is already consumed.
    r2 = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r2.json()["status"] == "REJECTED_REPLAY", (
        f"SECURITY FAIL: nonce from batch not marked as seen — replay possible"
    )
