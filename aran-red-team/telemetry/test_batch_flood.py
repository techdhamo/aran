"""
Aran Red-Team | Telemetry Test: Batch Flood / DoS Surface

Tests:
    B1 — Oversized batch: 600 events in one POST (exceeds MAX_QUEUE_SIZE=500 on device,
         but tests backend for unbounded iteration)
    B2 — Empty batch: [] → must not 500
    B3 — Malformed entries: batch with one valid + one missing required fields
    B4 — Concurrent flood: 50 concurrent single-event POSTs with unique nonces
         → all must return 202 without 5xx (virtual thread executor must handle load)
"""

import base64
import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import requests

from conftest import encrypt_payload, build_rbi_payload, build_envelope, BASE_URL

INGEST_URL = f"{BASE_URL}/api/v1/telemetry/ingest"
BATCH_URL  = f"{BASE_URL}/api/v1/telemetry/ingest/batch"


def _make_valid_envelope(rsa_pub_key):
    nonce = str(uuid.uuid4())
    ts = int(time.time() * 1000)
    plaintext = build_rbi_payload(nonce=nonce, timestamp=ts)
    blob = encrypt_payload(plaintext, rsa_pub_key)
    sha = base64.b64encode(hashlib.sha256(plaintext.encode()).digest()).decode()
    return build_envelope(blob, nonce, ts, payload_sha256=sha)


def test_B1_oversized_batch(rsa_pub_key):
    """600-event batch must not cause a 5xx; backend should process without OOM."""
    batch = [_make_valid_envelope(rsa_pub_key) for _ in range(600)]
    r = requests.post(BATCH_URL, json=batch, timeout=60)
    assert r.status_code in (202, 400, 413), (
        f"Unexpected status on oversized batch: {r.status_code} — {r.text[:200]}"
    )
    assert r.status_code != 500, "SECURITY FAIL: server returned 500 on oversized batch (DoS surface)"


def test_B2_empty_batch():
    """Empty batch array must return a 4xx or 202 — never 500."""
    r = requests.post(BATCH_URL, json=[], timeout=10)
    assert r.status_code != 500, f"Server 500 on empty batch: {r.text}"


def test_B3_malformed_batch_entry(rsa_pub_key):
    """Batch with one valid + one entry missing encrypted_blob must not 500."""
    valid = _make_valid_envelope(rsa_pub_key)
    malformed = {"schema_version": "2.0", "nonce": str(uuid.uuid4()), "timestamp": int(time.time() * 1000)}
    r = requests.post(BATCH_URL, json=[valid, malformed], timeout=10)
    assert r.status_code != 500, f"Server 500 on malformed batch entry: {r.text}"


def test_B4_concurrent_flood(rsa_pub_key):
    """50 concurrent valid POSTs — all must return 202 without 5xx."""
    envelopes = [_make_valid_envelope(rsa_pub_key) for _ in range(50)]
    results = []

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(requests.post, INGEST_URL, json=env, timeout=15): env
                   for env in envelopes}
        for future in as_completed(futures):
            try:
                r = future.result()
                results.append(r.status_code)
            except Exception as e:
                results.append(f"ERROR:{e}")

    failures = [s for s in results if s != 202]
    assert not failures, (
        f"SECURITY FAIL: {len(failures)} of 50 concurrent requests failed: {failures}"
    )
