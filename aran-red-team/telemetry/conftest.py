"""
Shared fixtures for Aran telemetry red-team tests.

Requires:
    pip install pytest cryptography requests

Set env vars before running:
    ARAN_TELEMETRY_URL=https://api.aran.mazhai.org   (or http://localhost:8083)
    ARAN_RSA_PUBLIC_KEY_PATH=/path/to/aran_pub.pem   (PEM format)
"""

import os
import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_URL = os.environ.get("ARAN_TELEMETRY_URL", "http://localhost:8083")
PUB_KEY_PATH = os.environ.get("ARAN_RSA_PUBLIC_KEY_PATH", "aran_pub.pem")


@pytest.fixture(scope="session")
def rsa_pub_key():
    with open(PUB_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


def encrypt_payload(plaintext: str, rsa_pub_key) -> str:
    """
    Replicate the SDK hybrid encryption:
      1. AES-256-GCM session key (ephemeral)
      2. Encrypt plaintext with AES-GCM
      3. RSA-OAEP encrypt session key
      4. Bundle {enc_key, iv, ct} → Base64
    """
    session_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ct = aesgcm.encrypt(iv, plaintext.encode(), None)

    enc_key = rsa_pub_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    bundle = {
        "enc_key": base64.b64encode(enc_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    bundle_bytes = json.dumps(bundle).encode()
    return base64.b64encode(bundle_bytes).decode()


def build_rbi_payload(nonce=None, timestamp=None, extra=None) -> str:
    nonce = nonce or str(uuid.uuid4())
    timestamp = timestamp or int(time.time() * 1000)
    payload = {
        "event_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "nonce": nonce,
        "timestamp": timestamp,
        "severity_level": "HIGH",
        "rasp_version": "1.0.0",
        "os_type": "android",
        "native_threat_mask": "0x3",
        "threat_vector": {
            "categories": ["PRIVILEGE_ESCALATION"],
            "is_rooted": True,
            "frida_detected": False,
            "debugger_attached": False,
            "emulator_detected": False,
            "hook_detected": False,
            "tampered": False,
            "untrusted_installer": False,
            "developer_mode": False,
            "adb_enabled": False,
            "env_tampering": False,
            "runtime_integrity": False,
            "proxy_detected": False,
            "zygisk_detected": False,
            "anon_elf_detected": False,
            "zygisk_fd_detected": False,
            "vpn_detected": False,
            "screen_recording": False,
            "keylogger_risk": False,
            "untrusted_keyboard": False,
            "device_lock_missing": False,
            "overlay_detected": False,
            "unsecured_wifi": False,
            "time_spoofing": False,
            "location_spoofing": False,
            "screen_mirroring": False,
            "malware_count": 0,
            "sms_forwarder_count": 0,
            "remote_access_count": 0,
        },
        "device_context": {
            "device_fingerprint": "test-fp-" + uuid.uuid4().hex[:8],
            "app_id": "org.mazhai.aran.test"
        }
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload)


def build_envelope(encrypted_blob: str, nonce: str, timestamp: int,
                   payload_sha256: str = None, schema_version: str = "2.0") -> dict:
    import hashlib
    return {
        "schema_version": schema_version,
        "enc_algorithm": "RSA-OAEP+AES-256-GCM",
        "encrypted_blob": encrypted_blob,
        "nonce": nonce,
        "timestamp": timestamp,
        "payload_sha256": payload_sha256 or "",
    }
