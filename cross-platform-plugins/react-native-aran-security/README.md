# react-native-aran-security

Enterprise mobile security SDK for React Native with hardware attestation and cloud-managed threat intelligence.

## Installation

```sh
npm install react-native-aran-security
```

### iOS

```sh
cd ios && pod install
```

### Android

Add the Aran Security SDK module to your `android/settings.gradle`:

```gradle
include ':aran-secure'
project(':aran-secure').projectDir = new File(rootProject.projectDir, '../../aran-android-sdk/aran-secure')
```

## Usage

### Initialize SDK

```typescript
import AranSecurity from 'react-native-aran-security';

await AranSecurity.start({
  licenseKey: 'YOUR_LICENSE_KEY',
  expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
  environment: 'RELEASE', // 'DEV', 'UAT', or 'RELEASE'
  backendUrl: 'https://api.aran.mazhai.org',
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

### Listen for Threats

```typescript
const removeThreatListener = AranSecurity.addThreatListener((event) => {
  console.log('Threat detected:', event.status);
  console.log('Reaction policy:', event.reactionPolicy);

  // Custom threat handling
  if (event.reactionPolicy === 'CUSTOM') {
    showCustomSecurityWarning(event.status);
  }
});

// Remove listener when done
removeThreatListener();
```

### Enable Screenshot Prevention

```typescript
await AranSecurity.enableSecureWindow();
```

### Generate Hardware-Attested JWT

```typescript
const sigil = await AranSecurity.generateSigil();

// Use sigil in API requests
fetch('https://api.example.com/secure-endpoint', {
  headers: {
    'X-Aran-Sigil': sigil,
  },
});
```

### Security Utilities

```typescript
// Clear clipboard
await AranSecurity.clearClipboard();

// Get cloud sync status
const syncStatus = await AranSecurity.getSyncStatus();
console.log('Last sync:', new Date(syncStatus.lastSyncTimestamp));

// Get device fingerprint
const fingerprint = await AranSecurity.getDeviceFingerprint();
```

## API

### `start(options)`

Initialize the Aran Security SDK.

**Parameters:**
- `options.licenseKey` (string) - Your Aran license key
- `options.expectedSignature` (string) - Expected APK signature SHA-256
- `options.environment` ('DEV' | 'UAT' | 'RELEASE') - Environment mode
- `options.backendUrl` (string, optional) - Aran Cloud backend URL

**Returns:** `Promise<void>`

### `checkEnvironment()`

Perform a comprehensive security scan.

**Returns:** `Promise<DeviceStatus>`

### `addThreatListener(callback)`

Add a listener for threat detection events.

**Parameters:**
- `callback` ((event: ThreatEvent) => void) - Callback function

**Returns:** `() => void` - Function to remove the listener

### `handleThreats(status, reactionPolicy)`

Handle detected threats with specified policy.

**Parameters:**
- `status` (DeviceStatus) - Device status
- `reactionPolicy` (ReactionPolicy) - Reaction policy

**Returns:** `Promise<void>`

### `enableSecureWindow()`

Enable screenshot and screen recording prevention.

**Returns:** `Promise<void>`

### `disableSecureWindow()`

Disable screenshot prevention.

**Returns:** `Promise<void>`

### `getSyncStatus()`

Get cloud sync status.

**Returns:** `Promise<SyncStatus>`

### `getDeviceFingerprint()`

Get device fingerprint.

**Returns:** `Promise<string>`

### `clearClipboard()`

Clear clipboard (security utility).

**Returns:** `Promise<void>`

### `generateSigil()`

Generate Aran Sigil (hardware-attested JWT).

**Returns:** `Promise<string>`

## Types

### `DeviceStatus`

```typescript
interface DeviceStatus {
  // Native detections
  isRooted: boolean;
  fridaDetected: boolean;
  debuggerAttached: boolean;
  emulatorDetected: boolean;
  hooked: boolean;
  tampered: boolean;
  untrustedInstaller: boolean;
  developerMode: boolean;
  adbEnabled: boolean;
  envTampering: boolean;
  runtimeIntegrity: boolean;
  proxyDetected: boolean;

  // Kotlin detections
  vpnDetected: boolean;
  screenRecording: boolean;
  keyloggerRisk: boolean;
  untrustedKeyboard: boolean;
  deviceLockMissing: boolean;
  overlayDetected: boolean;
  unsecuredWifi: boolean;

  // Lists
  malwarePackages: string[];
  smsForwarderApps: string[];
  remoteAccessApps: string[];

  // Metadata
  deviceFingerprint: string;
  appId: string;
  hasThreat: boolean;
  threatCount: number;
}
```

## Platform Support

- ✅ Android 7.0+ (API 24+)
- ✅ iOS 12.0+ (coming soon)

## License

Proprietary - Aran Security Platform

## Support

- Email: support@aran.mazhai.org
- Docs: https://docs.aran.mazhai.org
- Dashboard: https://dashboard.aran.mazhai.org
