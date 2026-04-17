# Aran RASP SDK — Security Policy and Incident Response

**Version:** 1.0  
**Last Updated:** 2026-04-17  
**Owner:** Mazhai Technologies Security Team  
**Contact:** security@mazhai.org

---

## Table of Contents

1. [Supported Versions](#supported-versions)
2. [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
3. [Incident Response Procedures](#incident-response-procedures)
4. [Key Rotation Policy](#key-rotation-policy)
5. [Cryptographic Material Management](#cryptographic-material-management)
6. [SOC Integration](#soc-integration)
7. [Compliance Frameworks](#compliance-frameworks)

---

## Supported Versions

| Version | Status | Support End Date |
|---------|--------|------------------|
| 1.0.x | ✅ Active | 2027-04-17 |
| 0.9.x | ⚠️ Maintenance | 2026-10-17 |
| < 0.9 | ❌ End of Life | - |

Security updates are backported to all **Active** and **Maintenance** versions.

---

## Reporting Security Vulnerabilities

### Responsible Disclosure

We follow responsible disclosure practices. Please report vulnerabilities privately before public disclosure.

**Email:** `security@mazhai.org`  
**PGP Key:** [security@mazhai.org.asc](./keys/security@mazhai.org.asc)  
**HackerOne:** [hackerone.com/mazhai](https://hackerone.com/mazhai)  
**Bug Bounty:** Up to $10,000 for critical RASP bypasses

### What to Report

- ✅ RASP/Frida detection bypasses
- ✅ Genesis Anchor extraction techniques
- ✅ Phantom Channel MITM attacks
- ✅ E2EE protocol weaknesses
- ✅ Keystore/Keychain extraction
- ✅ Memory dump vulnerabilities

### What NOT to Report

- ❌ Theoretical attacks without PoC
- ❌ Social engineering
- ❌ Physical device access (out of scope)
- ❌ Attacks requiring root/jailbreak (expected behavior)

### Response Timeline

| Severity | Acknowledgment | Initial Response | Fix Released |
|----------|----------------|------------------|--------------|
| Critical | 24 hours | 72 hours | 7 days |
| High | 48 hours | 7 days | 14 days |
| Medium | 7 days | 14 days | 30 days |
| Low | 14 days | 30 days | 60 days |

---

## Incident Response Procedures

### Severity Classifications

#### 🔴 Critical (P1)
- Genesis keys extracted from production builds
- RASP bypass published publicly
- Mass device compromise detected
- Backend API key leakage

**Response:** Immediate page to on-call, war room within 1 hour, public disclosure if customer-affecting.

#### 🟠 High (P2)
- Single SDK version bypass technique
- Partial key exposure (development only)
- Phantom Channel DoS vulnerability
- SDK tampering in supply chain

**Response:** Work hours response, patch within 72 hours.

#### 🟡 Medium (P3)
- Documentation inaccuracies affecting security
- Build system vulnerabilities
- Third-party dependency CVEs

**Response:** Scheduled fix in next sprint.

### Incident Response Playbook

#### When `invokeThreatKill()` Fires (MITM Detection)

```kotlin
// Automated response chain
1. Device sends encrypted crash telemetry with incident ID
2. Backend logs to SIEM (Splunk/Datadog) with high severity
3. Device fingerprint added to temporary watchlist
4. SOC analyst notified via PagerDuty
5. If >100 incidents in 10 minutes → auto-scale threat rules
```

#### When `AranScorchedEarth.execute()` Activates

```kotlin
// 3-phase response
1. SHRED phase: Device wipes all secrets (irreversible)
2. SEVER phase: Network blackhole activated
3. FREEZE phase: Device UI locked, user must force-stop

// Backend actions:
- Revoke all session tokens for device fingerprint
- Add fingerprint to 24-hour cool-down list
- Alert customer security team if enterprise license
- Preserve incident forensics (encrypted blob)
```

#### Supply Chain Compromise Response

```bash
# If build system is suspected compromised:
1. Halt all releases immediately
2. Rotate all CI/CD secrets (GitHub, AWS, signing keys)
3. Audit all commits since last known-good build
4. Rebuild from clean environment with new keys
5. Force-update all production apps (emergency release)
6. Notify customers via security advisory
```

---

## Key Rotation Policy

### Rotation Schedule

| Key Type | Rotation Interval | Emergency Rotation Trigger |
|----------|-------------------|---------------------------|
| AES-256 (E2EE) | 90 days | Any backend breach suspicion |
| HMAC-SHA256 | 90 days | Same as AES (used together) |
| TLS Certificate Pins | 60 days | Certificate renewal or breach |
| Blinding Salt | Per-build (always random) | N/A |
| Signing Keys | 1 year | Key exfiltration confirmed |

### Rotation Grace Period

**Dual-key support** allows gradual rotation:

```yaml
# application.yml during rotation
aran:
  crypto:
    active-key-id: "v2"
    keys:
      v1:
        aes-key: ${ARAN_AES_KEY_V1}  # old, expiring
        hmac-secret: ${ARAN_HMAC_V1}
        valid-until: "2026-07-17"
      v2:
        aes-key: ${ARAN_AES_KEY_V2}  # new, primary
        hmac-secret: ${ARAN_HMAC_V2}
        valid-from: "2026-04-17"
```

SDK accepts both keys during 7-day grace period, then rejects old keys.

### Manual Rotation Procedure

```bash
# 1. Generate new keys
NEW_AES=$(openssl rand -hex 32)
NEW_HMAC=$(openssl rand -hex 32)

# 2. Update GitHub Actions secrets
github secrets set ARAN_AES_KEY_V2 "$NEW_AES" --repo techdhamo/aran
github secrets set ARAN_HMAC_V2 "$NEW_HMAC" --repo techdhamo/aran

# 3. Trigger production build
gh workflow run production-release.yml

# 4. Monitor for decryption failures (should be 0% during grace period)
# 5. After 7 days, remove old keys
```

---

## Cryptographic Material Management

### Key Generation Standards

```python
# AES-256: os.urandom(32) or secrets.token_bytes(32)
# HMAC-256: Same entropy source
# Salt: Always 16 bytes, random per-build
# IV: 12 bytes, random per-encryption (never reused)
```

### Storage Requirements

| Environment | Storage | Access Control |
|-------------|---------|----------------|
| CI/CD | GitHub Secrets + AWS KMS | Restricted to release workflow |
| Production Backend | HashiCorp Vault | Role-based, audit logged |
| SDK Binary | XOR-chain encoded const blobs | Compile-time only |
| Device | StrongBox/Secure Enclave | Hardware-backed, no export |

### Prohibited Practices

🚫 **NEVER:**
- Commit plaintext keys to git (even "test" keys)
- Share keys via email/Slack
- Hardcode keys in source files
- Use same keys across dev/staging/prod
- Skip rotation due to "convenience"

✅ **ALWAYS:**
- Use separate keys per environment
- Rotate on employee offboarding
- Audit access logs quarterly
- Test disaster recovery ("oops, all keys leaked" drill)

---

## SOC Integration

### SIEM Alert Rules

#### Splunk SPL Queries

```spl
# Critical: Mass Scorched Earth activation
index=aran source="telemetry" event_type="SCORCHED_EARTH"
| stats count by device_fingerprint, _time
| where count > 5
| alert severity=critical "Mass device wipe detected"

# High: MITM attempts on Phantom Channel
index=aran source="phantom_sync" result="CERT_PIN_MISMATCH"
| stats count by src_ip
| where count > 10
| alert severity=high "Possible proxy/MITM attack"

# Medium: Frida detection spikes
index=aran source="rasp" threat="FRIDA_DETECTED"
| timechart span=1h count
| where count > 100
| alert severity=medium "Unusual Frida detection rate"
```

#### Datadog Monitors

```yaml
# monitors/aran-critical.yaml
alerts:
  - name: "Aran Genesis Decryption Failures"
    query: "sum:aran.genesis.decrypt_fail{*}.as_count() > 10"
    message: "@pagerduty-SOC-urgent Potential key compromise"
    priority: P1

  - name: "Phantom Channel MITM Detection"
    query: "avg:aran.phantom.mitm_detected{*} > 0"
    message: "@security-team MITM attempt on config sync"
    priority: P2
```

### Incident Forensics

When Scorched Earth activates, preserved data:

```json
{
  "incident_id": "uuid-v4",
  "timestamp": "ISO8601",
  "device_fingerprint": "SHA-256 hash",
  "threat_mask": "0x7FFF",
  "reason": "MITM detected on Phantom Channel",
  "app_version": "1.0.0",
  "os_version": "Android 14",
  "sdk_version": "1.0.0",
  "encrypted_blob": "AES-256-GCM encrypted device state"
}
```

**Retention:** 90 days encrypted, then purged per GDPR.

---

## Compliance Frameworks

### RBI (India) Compliance

| RBI NPCI Requirement | Aran Implementation | Evidence |
|----------------------|---------------------|----------|
| MFA for high-value | Device attestation (DCAppAttest/StrongBox) | `AranAppAttest.swift` |
| Transaction signing | E2EE with HMAC | `AranSyncEngine.kt:161-181` |
| Runtime tamper detection | 15-bit threat bitmask | `aran-core.cpp` |
| Incident reporting | SOC integration + forensics | This document |
| Data localization | India-region backend deployment | `mazhai-central` config |

### GDPR (EU) Compliance

- ✅ Data minimization: No PII in telemetry
- ✅ Right to erasure: Scorched Earth = immediate wipe
- ✅ Encryption: AES-256-GCM for all data
- ✅ Breach notification: 72-hour automated alert

### ISO 27001 Controls

| Control | Implementation |
|---------|------------------|
| A.10.1.1 | E2EE for all data transmission |
| A.10.1.2 | TLS 1.3 with certificate pinning |
| A.12.3.1 | RASP threat detection |
| A.16.1.4 | This incident response plan |

---

## Security Contacts

| Role | Name | Email | PGP |
|------|------|-------|-----|
| CISO | Security Team | security@mazhai.org | [0xA1B2C3D4](./keys/security-pgp.asc) |
| On-Call SOC | 24/7 | soc-urgent@mazhai.org | - |
| Engineering | Tech Lead | techdhamo@outlook.in | On request |

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-04-17 | 1.0 | Initial security policy |

---

**Document Classification:** PUBLIC  
**Next Review:** 2026-07-17
