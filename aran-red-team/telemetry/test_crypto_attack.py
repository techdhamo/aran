"""
Aran Red-Team | Telemetry Test: Cryptographic Attack Suite

Tests:
    C1 — Wrong RSA key: blob encrypted with an attacker-generated key → REJECTED_DECRYPT
    C2 — Truncated blob: base64 of valid structure but ciphertext byte-flipped → REJECTED_DECRYPT
    C3 — SHA-256 mismatch: valid encryption but tampered payload_sha256 → REJECTED_INTEGRITY
    C4 — Wrong schema version: schema_version != "2.0" → REJECTED_SCHEMA
    C5 — Raw plaintext blob: un-encrypted JSON sent as encrypted_blob → REJECTED_DECRYPT
    C6 — AES-GCM tag corruption: flip one byte in the ciphertext GCM tag → REJECTED_DECRYPT
"""

import base64
import hashlib
import json
import os
import time
import uuid

import pytest
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from conftest import (
    encrypt_payload, build_rbi_payload, build_envelope, BASE_URL
)

INGEST_URL = f"{BASE_URL}/api/v1/telemetry/ingest"


def _fresh_nonce_ts():
    return str(uuid.uuid4()), int(time.time() * 1000)


def test_C1_wrong_rsa_key(rsa_pub_key):
    """Blob encrypted with an attacker-generated RSA key must fail decryption."""
    # Generate a throwaway attacker key
    attacker_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()

    nonce, ts = _fresh_nonce_ts()
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, attacker_key)   # wrong key
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_DECRYPT", (
        f"SECURITY FAIL: blob encrypted with wrong key was accepted! Response: {body}"
    )


def test_C2_truncated_blob():
    """A truncated/malformed base64 blob must fail decryption."""
    nonce, ts = _fresh_nonce_ts()
    envelope = build_envelope("aGVsbG8=", nonce, ts)   # "hello" is not a valid bundle

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_DECRYPT", (
        f"SECURITY FAIL: truncated blob accepted! Response: {body}"
    )


def test_C3_sha256_mismatch(rsa_pub_key):
    """Valid encryption but wrong payload_sha256 must be caught by integrity check."""
    nonce, ts = _fresh_nonce_ts()
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)

    wrong_sha = base64.b64encode(os.urandom(32)).decode()   # random, not matching
    envelope = build_envelope(blob, nonce, ts, payload_sha256=wrong_sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_INTEGRITY", (
        f"SECURITY FAIL: SHA-256 mismatch not detected! Response: {body}"
    )


def test_C4_wrong_schema_version(rsa_pub_key):
    """Schema version != '2.0' must be rejected before decryption."""
    nonce, ts = _fresh_nonce_ts()
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha, schema_version="1.0")

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_SCHEMA", (
        f"SECURITY FAIL: old schema version accepted! Response: {body}"
    )


def test_C5_raw_plaintext_blob():
    """Sending un-encrypted JSON as encrypted_blob must fail parsing/decryption."""
    nonce, ts = _fresh_nonce_ts()
    fake_blob = base64.b64encode(build_rbi_payload(nonce=nonce, timestamp=ts).encode()).decode()
    envelope = build_envelope(fake_blob, nonce, ts)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] in ("REJECTED_DECRYPT", "REJECTED_INTEGRITY", "REJECTED_PARSE"), (
        f"SECURITY FAIL: raw plaintext blob accepted! Response: {body}"
    )


def test_C6_gcm_tag_corruption(rsa_pub_key):
    """Flip the last byte of the AES-GCM ciphertext (GCM tag region) → AEAD auth failure."""
    nonce, ts = _fresh_nonce_ts()
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)

    # Build bundle manually so we can corrupt the ct field
    session_key = os.urandom(32)
    iv = os.urandom(12)
    ct = AESGCM(session_key).encrypt(iv, plaintext.encode(), None)

    from cryptography.hazmat.primitives.asymmetric import padding as apad
    enc_key_bytes = rsa_pub_key.encrypt(
        session_key,
        apad.OAEP(mgf=apad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Corrupt: flip last byte of ct (the GCM tag)
    ct_corrupted = bytearray(ct)
    ct_corrupted[-1] ^= 0xFF
    ct_corrupted = bytes(ct_corrupted)

    bundle = {
        "enc_key": base64.b64encode(enc_key_bytes).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct_corrupted).decode(),
    }
    blob = base64.b64encode(json.dumps(bundle).encode()).decode()
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    envelope = build_envelope(blob, nonce, ts, payload_sha256=sha)

    r = requests.post(INGEST_URL, json=envelope, timeout=10)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "REJECTED_DECRYPT", (
        f"SECURITY FAIL: GCM tag corruption not caught! Response: {body}"
    )
