# @aran-security/capacitor-plugin

Enterprise mobile security SDK for Capacitor with hardware attestation and cloud-managed threat intelligence.

## Install

```bash
npm install @aran-security/capacitor-plugin
npx cap sync
```

## API

<docgen-index>

* [`start(...)`](#start)
* [`checkEnvironment()`](#checkenvironment)
* [`setThreatListener(...)`](#setthreatlistener)
* [`handleThreats(...)`](#handlethreats)
* [`enableSecureWindow()`](#enablesecurewindow)
* [`disableSecureWindow()`](#disablesecurewindow)
* [`getSyncStatus()`](#getsyncstatus)
* [`getDeviceFingerprint()`](#getdevicefingerprint)
* [`clearClipboard()`](#clearclipboard)
* [`generateSigil()`](#generatesigil)

</docgen-index>

## Usage

### Initialize SDK

```typescript
import { AranSecurity } from '@aran-security/capacitor-plugin';

await AranSecurity.start({
  licenseKey: 'YOUR_LICENSE_KEY',
  expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
  environment: 'RELEASE', // 'DEV', 'UAT', or 'RELEASE'
  backendUrl: 'https://api.aran.mazhai.org'
});
```

### Perform Security Scan

```typescript
const status = await AranSecurity.checkEnvironment();

if (status.isRooted) {
  console.warn('Device is rooted!');
}

if (status.fridaDetected) {
  console.warn('Frida detected!');
}

if (status.hasThreat) {
  console.warn(`${status.threatCount} threats detected`);
}
```

### Set Threat Listener

```typescript
await AranSecurity.setThreatListener((data) => {
  console.log('Threat detected:', data.status);
  console.log('Reaction policy:', data.reactionPolicy);
  
  // Custom threat handling
  if (data.reactionPolicy === 'CUSTOM') {
    showCustomSecurityWarning(data.status);
  }
});
```

### Enable Screenshot Prevention

```typescript
await AranSecurity.enableSecureWindow();
```

### Generate Hardware-Attested JWT

```typescript
const { sigil } = await AranSecurity.generateSigil();

// Use sigil in API requests
fetch('https://api.example.com/secure-endpoint', {
  headers: {
    'X-Aran-Sigil': sigil
  }
});
```

## API Reference

<docgen-api>

### start(...)

```typescript
start(options: StartOptions) => Promise<void>
```

Initialize Aran Security SDK

| Param         | Type                                                  |
| ------------- | ----------------------------------------------------- |
| **`options`** | <code><a href="#startoptions">StartOptions</a></code> |

--------------------

### checkEnvironment()

```typescript
checkEnvironment() => Promise<DeviceStatus>
```

Perform comprehensive security scan

**Returns:** <code>Promise&lt;<a href="#devicestatus">DeviceStatus</a>&gt;</code>

--------------------

### setThreatListener(...)

```typescript
setThreatListener(callback: ThreatListenerCallback) => Promise<void>
```

Set threat detection listener

| Param          | Type                                                                      |
| -------------- | ------------------------------------------------------------------------- |
| **`callback`** | <code><a href="#threatlistenercallback">ThreatListenerCallback</a></code> |

--------------------

### handleThreats(...)

```typescript
handleThreats(options: HandleThreatsOptions) => Promise<void>
```

Handle detected threats with specified policy

| Param         | Type                                                                  |
| ------------- | --------------------------------------------------------------------- |
| **`options`** | <code><a href="#handlethreatsoptions">HandleThreatsOptions</a></code> |

--------------------

### enableSecureWindow()

```typescript
enableSecureWindow() => Promise<void>
```

Enable screenshot and screen recording prevention

--------------------

### disableSecureWindow()

```typescript
disableSecureWindow() => Promise<void>
```

Disable screenshot prevention

--------------------

### getSyncStatus()

```typescript
getSyncStatus() => Promise<SyncStatus>
```

Get cloud sync status

**Returns:** <code>Promise&lt;<a href="#syncstatus">SyncStatus</a>&gt;</code>

--------------------

### getDeviceFingerprint()

```typescript
getDeviceFingerprint() => Promise<{ fingerprint: string; }>
```

Get device fingerprint

**Returns:** <code>Promise&lt;{ fingerprint: string; }&gt;</code>

--------------------

### clearClipboard()

```typescript
clearClipboard() => Promise<void>
```

Clear clipboard (security utility)

--------------------

### generateSigil()

```typescript
generateSigil() => Promise<{ sigil: string; }>
```

Generate Aran Sigil (hardware-attested JWT)

**Returns:** <code>Promise&lt;{ sigil: string; }&gt;</code>

--------------------

</docgen-api>

## Platform Support

- ✅ Android 7.0+ (API 24+)
- ✅ iOS 12.0+ (coming soon)
- ❌ Web (not supported - native only)

## License

Proprietary - Aran Security Platform

## Support

- Email: support@aran.mazhai.org
- Docs: https://docs.aran.mazhai.org
- Dashboard: https://dashboard.aran.mazhai.org
