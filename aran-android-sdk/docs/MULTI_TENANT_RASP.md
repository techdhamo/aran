# Multi-Tenant SaaS RASP Platform

**Version:** 2.0.0  
**Last Updated:** February 2026

---

## Table of Contents

1. [Overview](#overview)
2. [The False Positive Problem](#the-false-positive-problem)
3. [Merge Strategy: (Global + Blacklist) - Whitelist](#merge-strategy)
4. [Architecture](#architecture)
5. [Database Schema](#database-schema)
6. [API Reference](#api-reference)
7. [Use Cases](#use-cases)
8. [Testing](#testing)

---

## Overview

The Multi-Tenant SaaS RASP platform transforms Aran Secure from a one-size-fits-all solution into a **client-specific threat intelligence system**. Each tenant (bank, fintech, enterprise) can:

- ✅ **Whitelist** legitimate apps that Aran's global intel flags as threats
- ✅ **Blacklist** custom threats specific to their business (e.g., competitor apps)
- ✅ **Override** security policies per client
- ✅ **Zero app updates** - changes apply on next SDK sync (60 seconds)

---

## The False Positive Problem

### Problem Statement

**Scenario:** Bank B uses TeamViewer (`com.teamviewer.quicksupport.market`) for legitimate customer support. However, Aran's global threat intelligence flags TeamViewer as a **remote access app** (potential security risk).

**Traditional RASP Behavior:**
```
User opens Bank B's mobile app
  ↓
SDK detects TeamViewer installed
  ↓
App terminates for ALL clients
  ↓
Bank B cannot use Aran Secure SDK ❌
```

**Multi-Tenant RASP Solution:**
```
Bank B Admin Dashboard
  ↓
POST /api/v1/admin/tenant/BANK_B_LICENSE/whitelist
Body: {"packages": ["com.teamviewer.quicksupport.market"]}
  ↓
Next SDK sync (within 60 seconds)
  ↓
TeamViewer REMOVED from Bank B's threat list
  ↓
App runs normally for Bank B ✅
Other clients still block TeamViewer ✅
```

---

## Merge Strategy

### Formula

```
Final_Threat_List = (Global_Threat_Intel + Tenant_Blacklist) - Tenant_Whitelist
```

### Step-by-Step Process

**Step A: Fetch Global Threat Intel**
```java
Set<String> global = getGlobalMalwarePackages("android");
// ["com.topjohnwu.magisk", "com.teamviewer.quicksupport.market", "com.anydesk.anydeskandroid"]
```

**Step B: Fetch Tenant Blacklist (Client Additions)**
```java
Set<String> tenantBlacklist = getTenantBlacklistMalware("BANK_A_LICENSE");
// ["com.competitor.bankapp"]  // Bank A wants to block competitor
```

**Step C: Fetch Tenant Whitelist (Client Exceptions)**
```java
Set<String> tenantWhitelist = getTenantWhitelistMalware("BANK_B_LICENSE");
// ["com.teamviewer.quicksupport.market"]  // Bank B uses TeamViewer for support
```

**Step D: Merge**
```java
Set<String> merged = new HashSet<>(global);
merged.addAll(tenantBlacklist);  // Add custom threats
merged.removeAll(tenantWhitelist);  // Remove exceptions
return new ArrayList<>(merged);
```

### Example Results

**Bank A (Strict Security):**
```json
{
  "malware_packages": [
    "com.topjohnwu.magisk",
    "com.teamviewer.quicksupport.market",
    "com.anydesk.anydeskandroid",
    "com.competitor.bankapp"  ← Added by Bank A
  ]
}
```

**Bank B (Customer Support Needs):**
```json
{
  "malware_packages": [
    "com.topjohnwu.magisk",
    "com.anydesk.anydeskandroid"
    // TeamViewer removed! ← Whitelisted by Bank B
  ]
}
```

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    mazhai-central Backend                    │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  ConfigSyncController                                  │ │
│  │         ↓                                               │ │
│  │  ConfigSyncService.buildPersonalizedConfig()          │ │
│  │         ↓                                               │ │
│  │  ┌──────────────────────────────────────────────────┐ │ │
│  │  │ Step A: GlobalThreatIntel (Android)             │ │ │
│  │  │   ["magisk", "teamviewer", "anydesk"]           │ │ │
│  │  └──────────────────────────────────────────────────┘ │ │
│  │         ↓                                               │ │
│  │  ┌──────────────────────────────────────────────────┐ │ │
│  │  │ Step B: TenantBlacklist (BANK_A_LICENSE)        │ │ │
│  │  │   ["competitor.app"]                             │ │ │
│  │  └──────────────────────────────────────────────────┘ │ │
│  │         ↓                                               │ │
│  │  ┌──────────────────────────────────────────────────┐ │ │
│  │  │ Step C: TenantWhitelist (BANK_A_LICENSE)        │ │ │
│  │  │   []                                              │ │ │
│  │  └──────────────────────────────────────────────────┘ │ │
│  │         ↓                                               │ │
│  │  Merge: (A + B) - C                                    │ │
│  │  ["magisk", "teamviewer", "anydesk", "competitor"]    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                         ▼
         ┌───────────────────────────────┐
         │    Android SDK (aran-secure)  │
         │                               │
         │  AranSyncEngine               │
         │    ↓                           │
         │  Fetch personalized JSON      │
         │    ↓                           │
         │  Cache in EncryptedSharedPrefs│
         │    ↓                           │
         │  findMalwarePackages()        │
         │  reads from cache             │
         │  (NO client-side merging)     │
         └───────────────────────────────┘
```

---

## Database Schema

### GlobalThreatIntel

```sql
CREATE TABLE global_threat_intel (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    os_type VARCHAR(20) NOT NULL UNIQUE,  -- 'android' or 'ios'
    version VARCHAR(20) NOT NULL,
    last_updated TIMESTAMP NOT NULL,
    update_notes VARCHAR(500)
);

CREATE TABLE global_malware_packages (
    intel_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (intel_id) REFERENCES global_threat_intel(id)
);

CREATE TABLE global_sms_forwarders (
    intel_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (intel_id) REFERENCES global_threat_intel(id)
);

CREATE TABLE global_remote_access_apps (
    intel_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (intel_id) REFERENCES global_threat_intel(id)
);

CREATE TABLE global_ssl_pins (
    intel_id BIGINT,
    pin_hash VARCHAR(100),
    FOREIGN KEY (intel_id) REFERENCES global_threat_intel(id)
);
```

### TenantConfig

```sql
CREATE TABLE tenant_config (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_key VARCHAR(100) NOT NULL UNIQUE,
    company_name VARCHAR(255) NOT NULL,
    contact_email VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    
    -- Security Policy Overrides (NULL = use global defaults)
    kill_on_root BOOLEAN,
    kill_on_frida BOOLEAN,
    kill_on_debugger BOOLEAN,
    kill_on_emulator BOOLEAN,
    kill_on_hook BOOLEAN,
    kill_on_tamper BOOLEAN,
    kill_on_malware BOOLEAN,
    kill_on_proxy BOOLEAN,
    kill_on_vpn BOOLEAN,
    
    notes VARCHAR(1000)
);
```

### TenantBlacklist

```sql
CREATE TABLE tenant_blacklist (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_key VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    reason VARCHAR(500)
);

CREATE TABLE tenant_malware_additions (
    blacklist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (blacklist_id) REFERENCES tenant_blacklist(id)
);

CREATE TABLE tenant_sms_forwarder_additions (
    blacklist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (blacklist_id) REFERENCES tenant_blacklist(id)
);

CREATE TABLE tenant_remote_access_additions (
    blacklist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (blacklist_id) REFERENCES tenant_blacklist(id)
);
```

### TenantWhitelist

```sql
CREATE TABLE tenant_whitelist (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_key VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    reason VARCHAR(500)
);

CREATE TABLE tenant_malware_exceptions (
    whitelist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (whitelist_id) REFERENCES tenant_whitelist(id)
);

CREATE TABLE tenant_sms_forwarder_exceptions (
    whitelist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (whitelist_id) REFERENCES tenant_whitelist(id)
);

CREATE TABLE tenant_remote_access_exceptions (
    whitelist_id BIGINT,
    package_name VARCHAR(255),
    FOREIGN KEY (whitelist_id) REFERENCES tenant_whitelist(id)
);
```

---

## API Reference

### Config Sync API (SDK)

**Endpoint:** `GET /api/v1/config/sync`

**Query Parameters:**
- `os` (required): `android` or `ios`
- `rasp_version` (required): SDK version (e.g., `1.0.0`)
- `license_key` (required): Client license key

**Response:**
```json
{
  "config_version": "v1.1.0",
  "os_type": "android",
  "malware_packages": ["com.topjohnwu.magisk", "eu.chainfire.supersu"],
  "sms_forwarders": ["com.smsfwd", "com.jbak2.smsforwarder"],
  "remote_access_apps": ["com.anydesk.anydeskandroid"],
  "ssl_pins": ["sha256/AAAA...", "sha256/BBBB..."],
  "active_policy": {
    "kill_on_root": true,
    "kill_on_frida": true,
    "kill_on_debugger": true,
    "kill_on_emulator": true,
    "kill_on_hook": true,
    "kill_on_tamper": true,
    "kill_on_untrusted_installer": true,
    "kill_on_developer_mode": true,
    "kill_on_adb_enabled": true,
    "kill_on_proxy": false,
    "kill_on_vpn": false,
    "kill_on_malware": false
  },
  "sync_interval_seconds": 60
}
```

---

### Tenant Admin API (Dashboard)

#### Add to Whitelist

**Endpoint:** `POST /api/v1/admin/tenant/{license_key}/whitelist`

**Request Body:**
```json
{
  "packages": ["com.teamviewer.quicksupport.market"],
  "reason": "Used for customer support"
}
```

**Response:**
```json
{
  "license_key": "BANK_B_LICENSE",
  "packages": ["com.teamviewer.quicksupport.market"],
  "message": "Whitelist updated successfully. Next SDK sync will apply changes.",
  "timestamp": 1708646400000
}
```

#### Add to Blacklist

**Endpoint:** `POST /api/v1/admin/tenant/{license_key}/blacklist`

**Request Body:**
```json
{
  "packages": ["com.competitor.bankapp"],
  "reason": "Block competitor app"
}
```

**Response:**
```json
{
  "license_key": "BANK_A_LICENSE",
  "packages": ["com.competitor.bankapp"],
  "message": "Blacklist updated successfully. Next SDK sync will apply changes.",
  "timestamp": 1708646400000
}
```

#### Remove from Whitelist

**Endpoint:** `DELETE /api/v1/admin/tenant/{license_key}/whitelist`

**Request Body:**
```json
{
  "packages": ["com.teamviewer.quicksupport.market"]
}
```

#### Remove from Blacklist

**Endpoint:** `DELETE /api/v1/admin/tenant/{license_key}/blacklist`

**Request Body:**
```json
{
  "packages": ["com.competitor.bankapp"]
}
```

#### Get Tenant Config

**Endpoint:** `GET /api/v1/admin/tenant/{license_key}/config`

**Response:**
```json
{
  "license_key": "BANK_B_LICENSE",
  "company_name": "Bank B Corp",
  "whitelisted_packages": ["com.teamviewer.quicksupport.market"],
  "blacklisted_packages": [],
  "is_active": true,
  "last_modified": 1708646400000
}
```

---

## Use Cases

### Use Case 1: Bank Uses TeamViewer for Support

**Problem:** Bank B's customer support team uses TeamViewer to remotely assist customers. Aran's global intel blocks TeamViewer as a remote access threat.

**Solution:**
```bash
curl -X POST http://api.mazhai.org/api/v1/admin/tenant/BANK_B_LICENSE/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "packages": ["com.teamviewer.quicksupport.market"],
    "reason": "Customer support tool"
  }'
```

**Result:** Within 60 seconds, all Bank B mobile apps will no longer block TeamViewer. Other banks still block it.

---

### Use Case 2: Fintech Blocks Competitor App

**Problem:** Fintech A wants to prevent users from having competitor apps installed (business requirement).

**Solution:**
```bash
curl -X POST http://api.mazhai.org/api/v1/admin/tenant/FINTECH_A_LICENSE/blacklist \
  -H "Content-Type: application/json" \
  -d '{
    "packages": ["com.competitor.wallet"],
    "reason": "Competitor app - business policy"
  }'
```

**Result:** Fintech A's app will terminate if `com.competitor.wallet` is detected. Other clients unaffected.

---

### Use Case 3: Enterprise Whitelists Internal Tools

**Problem:** Enterprise C has internal admin tools that trigger Aran's remote access detection.

**Solution:**
```bash
curl -X POST http://api.mazhai.org/api/v1/admin/tenant/ENTERPRISE_C_LICENSE/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      "com.enterprise.internal.admin",
      "com.enterprise.internal.diagnostics"
    ],
    "reason": "Internal IT tools"
  }'
```

**Result:** Enterprise C employees can use internal tools without triggering RASP.

---

## Testing

### Backend Tests

**File:** `mazhai-central/src/test/java/org/mazhai/central/service/ConfigSyncServiceTest.java`

**Run:**
```bash
cd /Users/dhamo/lab/aran/mazhai-central
./mvnw test -Dtest=ConfigSyncServiceTest
```

**Test Cases:**
- ✅ Global threat intel for Android
- ✅ Global threat intel for iOS
- ✅ Tenant blacklist merging (Bank A)
- ✅ Tenant whitelist filtering (Bank B)
- ✅ Active policy defaults
- ✅ SSL pins inclusion
- ✅ No empty lists
- ✅ Config version consistency

---

### SDK Tests

**File:** `aran-android-sdk/aran-secure/src/androidTest/kotlin/org/mazhai/aran/AranSyncEngineTest.kt`

**Run:**
```bash
cd /Users/dhamo/lab/aran/aran-android-sdk
./gradlew :aran-secure:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.mazhai.aran.AranSyncEngineTest
```

**Test Cases:**
- ✅ Fallback defaults before first sync
- ✅ SMS forwarders fallback
- ✅ Remote access apps fallback
- ✅ SSL pins fallback
- ✅ Last sync timestamp initially zero
- ✅ Request ID persistence
- ✅ Network failure uses cached data
- ✅ Encrypted cache consistency
- ✅ Dynamic lists independence
- ✅ Stop cancels background sync

---

## Benefits Summary

| Feature | Traditional RASP | Multi-Tenant RASP |
|---------|------------------|-------------------|
| **False Positives** | Blocks all clients | Per-client exceptions |
| **Custom Threats** | Cannot add | Per-client blacklist |
| **Flexibility** | One-size-fits-all | Tailored per tenant |
| **Update Speed** | App update required | 60-second sync |
| **Client Satisfaction** | Rigid | Configurable |
| **Operational Cost** | High (support tickets) | Low (self-service) |

---

## Next Steps

1. **Implement JPA Repositories** - Replace in-memory data with database queries
2. **Add Authentication** - Secure admin API with OAuth2/JWT
3. **Build Dashboard UI** - React/Vue admin panel for whitelist/blacklist management
4. **Add Audit Logging** - Track all whitelist/blacklist changes
5. **Implement Rate Limiting** - Prevent abuse of admin API
6. **Add Webhooks** - Notify clients when config changes

---

**For implementation details, see:**
- [Integration Guide](INTEGRATION_GUIDE.md)
- [VAPT Testing Guide](VAPT_TESTING_GUIDE.md)
- [Technical Architecture](TECHNICAL_ARCHITECTURE.md)
