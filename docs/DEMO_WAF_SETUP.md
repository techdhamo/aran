# Demo WAF Setup Guide

**AranSentinel WAF Demo Configuration**

---

## Overview

This guide explains how to test the AranSentinel WAF with demo business endpoints while keeping RASP infrastructure calls separate.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Mazhai Central (Port 33100)                     │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  RASP Infrastructure (NO WAF)                          │ │
│  │  - GET  /api/v1/config/sync                            │ │
│  │  - POST /api/v1/telemetry/ingest                       │ │
│  │  - POST /api/v1/admin/tenant/{key}/whitelist           │ │
│  │  - GET  /api/v1/admin/tenant/{key}/config              │ │
│  │                                                         │ │
│  │  ✅ Excluded from WAF (shouldSkipWaf = true)           │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Demo Business API (WAF PROTECTED)                     │ │
│  │  - POST /api/v1/business/transfer-funds                │ │
│  │  - GET  /api/v1/business/account/{id}/balance          │ │
│  │  - POST /api/v1/business/payment/initiate              │ │
│  │  - PUT  /api/v1/business/profile                       │ │
│  │  - GET  /api/v1/business/transactions                  │ │
│  │                                                         │ │
│  │  ✅ Protected by AranSentinel WAF                      │ │
│  │  ✅ Requires X-Aran-Sigil header                       │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Start Backend with Demo Profile

```bash
cd /Users/dhamo/lab/aran/mazhai-central

# Start with demo profile (enables DemoBusinessApiController)
./mvnw spring-boot:run -Dspring-boot.run.profiles=demo
```

**Expected Output:**
```
AranSentinel WAF initialized
DemoBusinessApiController enabled
Server started on port 33100
```

---

### 2. Test RASP Endpoints (No WAF - Should Work)

**Config Sync (RASP SDK call):**
```bash
curl "http://localhost:33100/api/v1/config/sync?os=android&rasp_version=1.0.0&license_key=TEST_LICENSE"
```

**Expected:** ✅ 200 OK (no Sigil required)

**Telemetry (RASP SDK call):**
```bash
curl -X POST http://localhost:33100/api/v1/telemetry/ingest \
  -H "Content-Type: application/json" \
  -d '{"device_id":"test","threat_flags":0}'
```

**Expected:** ✅ 200 OK (no Sigil required)

---

### 3. Test Demo Business Endpoints (WAF Protected - Should Block)

**Transfer Funds (without Sigil):**
```bash
curl -X POST http://localhost:33100/api/v1/business/transfer-funds \
  -H "Content-Type: application/json" \
  -d '{"fromAccount":"12345","toAccount":"67890","amount":1000}'
```

**Expected:** ❌ 401 Unauthorized
```json
{
  "error": "MISSING_SIGIL",
  "message": "Hardware attestation required",
  "blocked_by": "AranSentinel WAF"
}
```

**Get Balance (without Sigil):**
```bash
curl http://localhost:33100/api/v1/business/account/12345/balance
```

**Expected:** ❌ 401 Unauthorized (same error)

---

### 4. Test with Mobile Demo App (Should Work)

**In the Android demo app:**

```kotlin
// The app already has AranSigilInterceptor configured
val retrofit = Retrofit.Builder()
    .baseUrl("http://10.0.2.2:33100")  // Emulator → localhost
    .client(okHttpClient)  // Has AranSigilInterceptor
    .build()

val api = retrofit.create(BusinessApi::class.java)

// This will succeed because Sigil is automatically attached
val response = api.transferFunds(TransferRequest("12345", "67890", 1000.0))
```

**Expected:** ✅ 200 OK (Sigil header present)

---

## WAF Configuration

### Default Settings (application-demo.yml)

```yaml
aran:
  demo:
    enabled: true  # Enable demo endpoints
  
  sentinel:
    waf:
      block-rooted: true       # Block rooted devices
      block-hooked: true       # Block Xposed/Frida
      block-emulator: false    # Allow emulators (for testing)
      block-tampered: true     # Block modified APKs
      block-frida: true        # Block Frida
      block-debugger: false    # Allow debuggers (for development)
```

### Production Settings

For production deployment, use stricter settings:

```yaml
aran:
  sentinel:
    waf:
      block-rooted: true
      block-hooked: true
      block-emulator: true      # Block emulators in production
      block-tampered: true
      block-frida: true
      block-debugger: true      # Block debuggers in production
```

---

## Endpoint Mapping

### WAF Filter Logic

The `AranSentinelWafFilter` automatically excludes RASP infrastructure:

```java
private boolean shouldSkipWaf(String uri) {
    return uri.startsWith("/api/v1/config/sync") ||      // ← RASP config
           uri.startsWith("/api/v1/telemetry/ingest") || // ← RASP telemetry
           uri.startsWith("/api/v1/attest") ||           // ← RASP attestation
           uri.startsWith("/api/v1/admin") ||            // ← Admin API
           uri.startsWith("/actuator") ||                // ← Spring Boot
           uri.startsWith("/public");                    // ← Public
}
```

**Result:**
- ✅ `/api/v1/business/*` → WAF validates Sigil
- ❌ `/api/v1/config/*` → WAF skipped
- ❌ `/api/v1/telemetry/*` → WAF skipped
- ❌ `/api/v1/admin/*` → WAF skipped

---

## Testing Scenarios

### Scenario 1: Bot Attack (Python Script)

**Attack:**
```python
import requests

response = requests.post(
    "http://localhost:33100/api/v1/business/transfer-funds",
    json={"fromAccount": "12345", "toAccount": "67890", "amount": 1000000}
)
print(response.status_code)  # 401
print(response.json())       # {"error": "MISSING_SIGIL", ...}
```

**Result:** ✅ Blocked (no hardware signature)

---

### Scenario 2: Rooted Device

**Mobile app on rooted device:**
- RASP detects root: `rasp_bitmask = 0x001`
- Sigil JWT includes: `"rasp_bitmask": 1`
- WAF reads bitmask and blocks

**Result:** ✅ Blocked with 403 DEVICE_ROOTED

---

### Scenario 3: MITM Attack

**Attacker intercepts request and modifies amount:**
- Original: `{"amount": 100}`
- Modified: `{"amount": 1000000}`
- Payload hash in Sigil: `sha256("{"amount": 100}")`
- WAF recomputes hash: `sha256("{"amount": 1000000}")`
- Hashes don't match

**Result:** ✅ Blocked with 403 PAYLOAD_TAMPERED

---

### Scenario 4: Legitimate Mobile App

**Mobile app with RASP SDK:**
- Device not rooted: `rasp_bitmask = 0`
- AranSigilInterceptor generates hardware-signed JWT
- Payload hash matches
- Timestamp within 60 seconds

**Result:** ✅ Allowed (200 OK)

---

## Monitoring

### View WAF Logs

```bash
# Watch WAF activity
tail -f logs/spring.log | grep AranSentinel

# Expected output:
# AranSentinel: Request validated successfully (device: abc123, bitmask: 0)
# SECURITY ALERT: Missing X-Aran-Sigil header - request blocked
# SECURITY ALERT: Rooted device detected - request blocked (bitmask: 1)
```

### Check Blocked Requests

```bash
# Count blocked requests by error type
grep "WAF_BLOCK" logs/spring.log | cut -d'=' -f2 | sort | uniq -c

# Example output:
#   45 MISSING_SIGIL
#   12 DEVICE_ROOTED
#    3 PAYLOAD_TAMPERED
#    1 SQL_INJECTION
```

---

## Troubleshooting

### Issue: Demo endpoints return 404

**Cause:** Demo profile not enabled

**Solution:**
```bash
# Ensure demo profile is active
./mvnw spring-boot:run -Dspring-boot.run.profiles=demo
```

---

### Issue: RASP calls blocked by WAF

**Cause:** WAF exclusion not working

**Solution:** Verify `shouldSkipWaf()` logic in `AranSentinelWafFilter.java`

---

### Issue: Mobile app requests blocked

**Cause:** Sigil not being generated

**Solution:**
1. Check `AranSigilInterceptor` is added to OkHttpClient
2. Verify Android KeyStore key exists
3. Check logs: `adb logcat | grep AranSigil`

---

## Production Deployment

### Separate Servers (Recommended)

**Best Practice:** Deploy WAF on customer business API server, not RASP infrastructure.

```
┌─────────────────────┐            ┌─────────────────────┐
│   Bank API Server   │            │   Aran Central      │
│  (api.bank.com)     │            │ (aran.mazhai.org)   │
│                     │            │                     │
│ @EnableAranSentinel │            │ NO WAF              │
│ ✅ Business APIs    │            │ ✅ RASP infra       │
└─────────────────────┘            └─────────────────────┘
```

**Advantages:**
- Clear separation of concerns
- No confusion about which endpoints are protected
- Easier to scale independently

---

## Summary

**Demo Setup:**
- ✅ WAF enabled on Mazhai Central
- ✅ Demo business endpoints protected
- ✅ RASP infrastructure excluded
- ✅ Mobile app can test end-to-end

**Production Setup:**
- ✅ WAF on customer business API server
- ✅ RASP infrastructure separate
- ✅ No circular dependencies

---

**For Support:**
- Documentation: https://docs.aran.mazhai.org
- WAF Guide: `/docs/ARANSENTINEL_WAF_INTEGRATION_GUIDE.md`
- Email: support@mazhai.org
