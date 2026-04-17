# Admin Tenant Management System - Complete Guide

**Aran Security Cloud - Multi-Tenant RASP Platform**

---

## 🎯 Overview

The Admin Tenant Management System provides complete control over tenant configuration, security policies, and behavior customization for the Aran RASP platform.

**Key Features:**
- ✅ Full CRUD operations for tenant management
- ✅ RASP behavior configuration (block/allow per threat type)
- ✅ Reaction policy management (LOG_ONLY, WARN_USER, BLOCK_API, KILL_APP, BLOCK_AND_REPORT)
- ✅ Whitelist/Blacklist management
- ✅ SSL certificate pinning configuration
- ✅ Per-tenant security policies

---

## 📊 Architecture

### Database Schema

**Tenant Entity:**
```sql
CREATE TABLE tenants (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_key VARCHAR(100) UNIQUE NOT NULL,
    organization_name VARCHAR(200) NOT NULL,
    contact_email VARCHAR(100),
    contact_phone VARCHAR(20),
    status VARCHAR(20) NOT NULL,  -- ACTIVE, SUSPENDED, TRIAL, EXPIRED
    tier VARCHAR(20) NOT NULL,    -- TRIAL, STANDARD, PREMIUM, ENTERPRISE
    
    -- RASP Behavior Flags
    block_on_root BOOLEAN DEFAULT TRUE,
    block_on_frida BOOLEAN DEFAULT TRUE,
    block_on_debugger BOOLEAN DEFAULT FALSE,
    block_on_emulator BOOLEAN DEFAULT FALSE,
    block_on_hooked BOOLEAN DEFAULT TRUE,
    block_on_tampered BOOLEAN DEFAULT TRUE,
    block_on_untrusted_installer BOOLEAN DEFAULT TRUE,
    
    -- Reaction Policies
    root_detection_reaction VARCHAR(20) DEFAULT 'BLOCK_API',
    frida_detection_reaction VARCHAR(20) DEFAULT 'BLOCK_API',
    tampered_apk_reaction VARCHAR(20) DEFAULT 'KILL_APP',
    malware_detection_reaction VARCHAR(20) DEFAULT 'KILL_APP',
    
    -- Configuration
    api_base_url VARCHAR(500),
    max_devices INT DEFAULT 1000,
    current_devices INT DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_sync_at TIMESTAMP
);

CREATE TABLE tenant_ssl_pins (
    tenant_id BIGINT,
    certificate_hash VARCHAR(64),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
```

---

## 🔌 API Endpoints

### Base URL
```
http://localhost:33100/api/v1/admin/tenants
```

---

## 1️⃣ Tenant CRUD Operations

### Create Tenant
```http
POST /api/v1/admin/tenants
Content-Type: application/json

{
  "licenseKey": "BANK_C_LICENSE",
  "organizationName": "Bank C Financial Services",
  "contactEmail": "security@bankc.com",
  "contactPhone": "+1-555-0103",
  "tier": "PREMIUM",
  "maxDevices": 5000,
  "apiBaseUrl": "https://api.bankc.com"
}
```

**Response:**
```json
{
  "id": 3,
  "licenseKey": "BANK_C_LICENSE",
  "organizationName": "Bank C Financial Services",
  "contactEmail": "security@bankc.com",
  "status": "ACTIVE",
  "tier": "PREMIUM",
  "raspBehavior": {
    "blockOnRoot": true,
    "blockOnFrida": true,
    "blockOnDebugger": false,
    "blockOnEmulator": false,
    "blockOnHooked": true,
    "blockOnTampered": true,
    "blockOnUntrustedInstaller": true
  },
  "reactionPolicies": {
    "rootDetectionReaction": "BLOCK_API",
    "fridaDetectionReaction": "BLOCK_API",
    "tamperedApkReaction": "KILL_APP",
    "malwareDetectionReaction": "KILL_APP"
  },
  "sslCertificatePins": [],
  "maxDevices": 5000,
  "currentDevices": 0,
  "createdAt": "2026-02-23T00:00:00"
}
```

---

### Get All Tenants
```http
GET /api/v1/admin/tenants
```

---

### Get Tenant by License Key
```http
GET /api/v1/admin/tenants/BANK_A_LICENSE
```

---

### Update Tenant
```http
PUT /api/v1/admin/tenants/3
Content-Type: application/json

{
  "organizationName": "Bank C Corp",
  "contactEmail": "new-security@bankc.com",
  "status": "ACTIVE",
  "tier": "ENTERPRISE",
  "maxDevices": 10000
}
```

---

### Delete Tenant
```http
DELETE /api/v1/admin/tenants/3
```

---

## 2️⃣ RASP Behavior Configuration

### Update RASP Blocking Behavior

Configure which threats should block the app vs. just log.

```http
PUT /api/v1/admin/tenants/BANK_A_LICENSE/rasp-behavior
Content-Type: application/json

{
  "blockOnRoot": true,
  "blockOnFrida": true,
  "blockOnDebugger": false,
  "blockOnEmulator": false,
  "blockOnHooked": true,
  "blockOnTampered": true,
  "blockOnUntrustedInstaller": true
}
```

**Use Cases:**
- **Production:** Block root, frida, hooks, tampering
- **UAT:** Allow debugger and emulator for testing
- **Development:** Allow everything except tampering

---

## 3️⃣ Reaction Policy Configuration

### Update Reaction Policies

Define what happens when each threat is detected.

```http
PUT /api/v1/admin/tenants/BANK_A_LICENSE/reaction-policies
Content-Type: application/json

{
  "rootDetectionReaction": "BLOCK_API",
  "fridaDetectionReaction": "KILL_APP",
  "tamperedApkReaction": "KILL_APP",
  "malwareDetectionReaction": "BLOCK_AND_REPORT"
}
```

**Reaction Policy Options:**

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `LOG_ONLY` | Just log the event | Monitoring/analytics only |
| `WARN_USER` | Show warning dialog | User education |
| `BLOCK_API` | Block API calls, allow app | Graceful degradation |
| `KILL_APP` | Terminate immediately | Critical security threat |
| `BLOCK_AND_REPORT` | Block + send telemetry | Detailed forensics |

**Example Scenarios:**

**Scenario 1: Strict Security (Banking)**
```json
{
  "rootDetectionReaction": "KILL_APP",
  "fridaDetectionReaction": "KILL_APP",
  "tamperedApkReaction": "KILL_APP",
  "malwareDetectionReaction": "KILL_APP"
}
```

**Scenario 2: Balanced (E-commerce)**
```json
{
  "rootDetectionReaction": "BLOCK_API",
  "fridaDetectionReaction": "BLOCK_API",
  "tamperedApkReaction": "KILL_APP",
  "malwareDetectionReaction": "WARN_USER"
}
```

**Scenario 3: Monitoring Only (Analytics)**
```json
{
  "rootDetectionReaction": "LOG_ONLY",
  "fridaDetectionReaction": "LOG_ONLY",
  "tamperedApkReaction": "LOG_ONLY",
  "malwareDetectionReaction": "LOG_ONLY"
}
```

---

## 4️⃣ SSL Certificate Pinning

### Add SSL Certificate Pin
```http
POST /api/v1/admin/tenants/BANK_A_LICENSE/ssl-pins
Content-Type: application/json

{
  "certificateHash": "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
```

---

### Remove SSL Certificate Pin
```http
DELETE /api/v1/admin/tenants/BANK_A_LICENSE/ssl-pins/sha256%2FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D
```

---

### Update All SSL Pins
```http
PUT /api/v1/admin/tenants/BANK_A_LICENSE/ssl-pins
Content-Type: application/json

{
  "certificateHashes": [
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
  ]
}
```

**How to Get Certificate Hash:**
```bash
# From PEM file
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  base64

# From live server
openssl s_client -connect api.bank.com:443 < /dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  base64
```

---

## 5️⃣ Whitelist Management

### Get Whitelist
```http
GET /api/v1/admin/tenants/BANK_A_LICENSE/whitelist
```

---

### Add to Whitelist
```http
POST /api/v1/admin/tenants/BANK_A_LICENSE/whitelist
Content-Type: application/json

{
  "packageName": "com.teamviewer.quicksupport.market",
  "reason": "Approved for customer support",
  "category": "REMOTE_ACCESS"
}
```

**Response:**
```json
{
  "status": "added",
  "package": "com.teamviewer.quicksupport.market"
}
```

---

### Remove from Whitelist
```http
DELETE /api/v1/admin/tenants/BANK_A_LICENSE/whitelist/com.teamviewer.quicksupport.market
```

---

## 6️⃣ Blacklist Management

### Get Blacklist
```http
GET /api/v1/admin/tenants/BANK_A_LICENSE/blacklist
```

---

### Add to Blacklist
```http
POST /api/v1/admin/tenants/BANK_A_LICENSE/blacklist
Content-Type: application/json

{
  "packageName": "com.competitor.banking",
  "reason": "Competitor app - potential data leakage",
  "category": "MALWARE"
}
```

---

### Remove from Blacklist
```http
DELETE /api/v1/admin/tenants/BANK_A_LICENSE/blacklist/com.competitor.banking
```

---

## 🔄 Complete Workflow Example

### Scenario: Onboarding Bank D

**Step 1: Create Tenant**
```bash
curl -X POST http://localhost:33100/api/v1/admin/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "licenseKey": "BANK_D_LICENSE",
    "organizationName": "Bank D",
    "contactEmail": "security@bankd.com",
    "tier": "ENTERPRISE",
    "maxDevices": 10000,
    "apiBaseUrl": "https://api.bankd.com"
  }'
```

**Step 2: Configure RASP Behavior (Production)**
```bash
curl -X PUT http://localhost:33100/api/v1/admin/tenants/BANK_D_LICENSE/rasp-behavior \
  -H "Content-Type: application/json" \
  -d '{
    "blockOnRoot": true,
    "blockOnFrida": true,
    "blockOnDebugger": true,
    "blockOnEmulator": true,
    "blockOnHooked": true,
    "blockOnTampered": true,
    "blockOnUntrustedInstaller": true
  }'
```

**Step 3: Set Strict Reaction Policies**
```bash
curl -X PUT http://localhost:33100/api/v1/admin/tenants/BANK_D_LICENSE/reaction-policies \
  -H "Content-Type: application/json" \
  -d '{
    "rootDetectionReaction": "KILL_APP",
    "fridaDetectionReaction": "KILL_APP",
    "tamperedApkReaction": "KILL_APP",
    "malwareDetectionReaction": "KILL_APP"
  }'
```

**Step 4: Add SSL Certificate Pins**
```bash
curl -X POST http://localhost:33100/api/v1/admin/tenants/BANK_D_LICENSE/ssl-pins \
  -H "Content-Type: application/json" \
  -d '{
    "certificateHash": "sha256/BankDPrimaryCertHash="
  }'
```

**Step 5: Add Approved Remote Access Tool to Whitelist**
```bash
curl -X POST http://localhost:33100/api/v1/admin/tenants/BANK_D_LICENSE/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "packageName": "com.teamviewer.quicksupport.market",
    "reason": "Approved for customer support operations",
    "category": "REMOTE_ACCESS"
  }'
```

**Step 6: Add Competitor App to Blacklist**
```bash
curl -X POST http://localhost:33100/api/v1/admin/tenants/BANK_D_LICENSE/blacklist \
  -H "Content-Type: application/json" \
  -d '{
    "packageName": "com.competitor.banking",
    "reason": "Competitor app - security policy",
    "category": "MALWARE"
  }'
```

---

## 📱 Integration with Ionic Dashboard

The Ionic dashboard (`aran-dashboard`) provides a UI for all these operations:

**Tenant Dashboard Page:**
- License key input
- Whitelist/Blacklist management with add/remove UI
- Environment selector
- Real-time sync status

**Connect to Backend:**
```typescript
// src/services/api.ts
const API_BASE_URL = 'http://localhost:33100'

export const tenantApi = {
  createTenant: async (data: CreateTenantRequest) => {
    const response = await axios.post(`${API_BASE_URL}/api/v1/admin/tenants`, data)
    return response.data
  },
  
  updateRaspBehavior: async (licenseKey: string, behavior: RaspBehaviorRequest) => {
    const response = await axios.put(
      `${API_BASE_URL}/api/v1/admin/tenants/${licenseKey}/rasp-behavior`,
      behavior
    )
    return response.data
  },
  
  // ... other methods
}
```

---

## 🔒 Security Considerations

### Authentication (TODO)
Add Spring Security with JWT:
```java
@PreAuthorize("hasRole('ADMIN')")
@PostMapping
public ResponseEntity<TenantResponse> createTenant(@RequestBody CreateTenantRequest request) {
    // ...
}
```

### Audit Logging
All admin operations should be logged:
```java
@Aspect
public class AdminAuditAspect {
    @AfterReturning("@annotation(org.springframework.web.bind.annotation.PostMapping)")
    public void logAdminAction(JoinPoint joinPoint) {
        // Log to audit table
    }
}
```

---

## 📊 Database Migrations

**File:** `src/main/resources/db/migration/V1__create_tenants.sql`

```sql
CREATE TABLE tenants (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_key VARCHAR(100) UNIQUE NOT NULL,
    organization_name VARCHAR(200) NOT NULL,
    -- ... (see schema above)
);

CREATE TABLE tenant_ssl_pins (
    tenant_id BIGINT,
    certificate_hash VARCHAR(64),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX idx_license_key ON tenants(license_key);
CREATE INDEX idx_status ON tenants(status);
```

---

## ✅ Summary

The Admin Tenant Management System provides:

1. **Full CRUD** - Create, read, update, delete tenants
2. **RASP Configuration** - Per-tenant blocking behavior
3. **Reaction Policies** - Customizable threat responses
4. **SSL Pinning** - Certificate hash management
5. **Whitelist/Blacklist** - Tenant-specific exceptions
6. **Multi-Tier Support** - TRIAL, STANDARD, PREMIUM, ENTERPRISE
7. **Status Management** - ACTIVE, SUSPENDED, TRIAL, EXPIRED

**Files Created:**
- `Tenant.java` - JPA entity with all fields
- `TenantRepository.java` - Database access
- `TenantService.java` - Business logic
- `CompleteTenantAdminController.java` - REST API endpoints

**Next Steps:**
1. Add Spring Security authentication
2. Implement audit logging
3. Create database migrations
4. Connect Ionic dashboard
5. Add integration tests

---

**For Support:** support@aran.mazhai.org  
**Documentation:** https://docs.aran.mazhai.org
