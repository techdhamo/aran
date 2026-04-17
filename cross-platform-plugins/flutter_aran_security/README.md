# flutter_aran_security

Enterprise mobile security SDK for Flutter with hardware attestation and cloud-managed threat intelligence.

## Installation

Add this to your package's `pubspec.yaml` file:

```yaml
dependencies:
  flutter_aran_security: ^1.0.0
```

### Android

Add the Aran Security SDK module to your `android/settings.gradle`:

```gradle
include ':aran-secure'
project(':aran-secure').projectDir = new File(rootProject.projectDir, '../../aran-android-sdk/aran-secure')
```

### iOS

Coming soon.

## Usage

### Initialize SDK

```dart
import 'package:flutter_aran_security/flutter_aran_security.dart';

await AranSecurity.start(
  StartOptions(
    licenseKey: 'YOUR_LICENSE_KEY',
    expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
    environment: AranEnvironment.release,
  ),
);
```

### Perform Security Scan

```dart
final status = await AranSecurity.checkEnvironment();

if (status.isRooted) {
  print('Device is rooted!');
}

if (status.fridaDetected) {
  print('Frida detected!');
}

if (status.hasThreat) {
  print('${status.threatCount} threats detected');
}
```

### Listen for Threats

```dart
AranSecurity.threatStream.listen((event) {
  print('Threat detected: ${event.status.threatCount}');
  print('Reaction policy: ${event.reactionPolicy}');

  // Custom threat handling
  if (event.reactionPolicy == 'CUSTOM') {
    showCustomSecurityWarning(event.status);
  }
});
```

### Enable Screenshot Prevention

```dart
await AranSecurity.enableSecureWindow();
```

### Generate Hardware-Attested JWT

```dart
final sigil = await AranSecurity.generateSigil();

// Use sigil in API requests
final response = await http.get(
  Uri.parse('https://api.example.com/secure-endpoint'),
  headers: {'X-Aran-Sigil': sigil},
);
```

### Security Utilities

```dart
// Clear clipboard
await AranSecurity.clearClipboard();

// Get cloud sync status
final syncStatus = await AranSecurity.getSyncStatus();
print('Last sync: ${DateTime.fromMillisecondsSinceEpoch(syncStatus.lastSyncTimestamp)}');

// Get device fingerprint
final fingerprint = await AranSecurity.getDeviceFingerprint();
```

## API Reference

### `AranSecurity.start(StartOptions)`

Initialize the Aran Security SDK.

**Parameters:**
- `options.licenseKey` (String) - Your Aran license key
- `options.expectedSignature` (String) - Expected APK signature SHA-256
- `options.environment` (AranEnvironment) - Environment mode
- `options.backendUrl` (String?, optional) - Aran Cloud backend URL

**Returns:** `Future<void>`

### `AranSecurity.checkEnvironment()`

Perform a comprehensive security scan.

**Returns:** `Future<DeviceStatus>`

### `AranSecurity.threatStream`

Stream of threat detection events.

**Returns:** `Stream<ThreatEvent>`

### `AranSecurity.handleThreats(DeviceStatus, ReactionPolicy)`

Handle detected threats with specified policy.

**Returns:** `Future<void>`

### `AranSecurity.enableSecureWindow()`

Enable screenshot and screen recording prevention.

**Returns:** `Future<void>`

### `AranSecurity.disableSecureWindow()`

Disable screenshot prevention.

**Returns:** `Future<void>`

### `AranSecurity.getSyncStatus()`

Get cloud sync status.

**Returns:** `Future<SyncStatus>`

### `AranSecurity.getDeviceFingerprint()`

Get device fingerprint.

**Returns:** `Future<String>`

### `AranSecurity.clearClipboard()`

Clear clipboard (security utility).

**Returns:** `Future<void>`

### `AranSecurity.generateSigil()`

Generate Aran Sigil (hardware-attested JWT).

**Returns:** `Future<String>`

## Models

### `DeviceStatus`

Contains all security flags and threat information.

### `StartOptions`

Configuration for SDK initialization.

### `SyncStatus`

Cloud sync status information.

### `ThreatEvent`

Threat detection event with status and policy.

## Enums

### `AranEnvironment`

- `AranEnvironment.dev` - Development mode
- `AranEnvironment.uat` - UAT mode
- `AranEnvironment.release` - Production mode

### `ReactionPolicy`

- `ReactionPolicy.logOnly` - Log only
- `ReactionPolicy.warnUser` - Warn user
- `ReactionPolicy.blockApi` - Block API
- `ReactionPolicy.killApp` - Kill app
- `ReactionPolicy.blockAndReport` - Block and report
- `ReactionPolicy.custom` - Custom handling

## Platform Support

- ✅ Android 7.0+ (API 24+)
- 🔄 iOS 12.0+ (coming soon)

## License

Proprietary - Aran Security Platform

## Support

- Email: support@aran.mazhai.org
- Docs: https://docs.aran.mazhai.org
- Dashboard: https://dashboard.aran.mazhai.org
