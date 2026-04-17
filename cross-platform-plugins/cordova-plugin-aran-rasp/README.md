# Cordova Plugin - Aran RASP

Enterprise Runtime Application Self-Protection for Apache Cordova applications.

## 🛡️ Features

- ✅ Root/Jailbreak Detection (23 file artifacts + Magisk)
- ✅ Frida Detection (/proc/self/maps + port scanning)
- ✅ Debugger Detection (ptrace + TracerPid)
- ✅ Emulator/Simulator Detection
- ✅ Hook Detection (Xposed, Substrate, Cydia)
- ✅ APK/IPA Tampering Detection
- ✅ SSL Certificate Pinning
- ✅ Screenshot Prevention
- ✅ Cloud-Managed Configuration
- ✅ Real-time Telemetry
- ✅ Custom Threat Handlers

## 📦 Installation

```bash
cordova plugin add cordova-plugin-aran-rasp
```

Or from local path:
```bash
cordova plugin add /path/to/cordova-plugin-aran-rasp
```

## 🚀 Quick Start

### Initialize SDK

```javascript
document.addEventListener('deviceready', function() {
    AranRASP.initialize({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
        environment: 'RELEASE', // DEV, UAT, or RELEASE
        backendUrl: 'https://api.aran.mazhai.org'
    })
    .then(() => {
        console.log('Aran RASP initialized successfully');
        return AranRASP.checkEnvironment();
    })
    .then((status) => {
        console.log('Device Status:', status);
        
        if (status.hasThreat) {
            console.warn('Threats detected:', status.threatCount);
        }
    })
    .catch((error) => {
        console.error('Aran RASP error:', error);
    });
});
```

### Perform Security Scan

```javascript
AranRASP.checkEnvironment()
    .then((status) => {
        if (status.isRooted) {
            alert('Device is rooted!');
        }
        
        if (status.isFridaDetected) {
            alert('Frida detected!');
        }
        
        if (status.isTampered) {
            alert('App has been tampered!');
        }
    });
```

### Set Threat Listener

```javascript
AranRASP.setThreatListener((status, reactionPolicy) => {
    console.log('Threat detected!', status);
    console.log('Reaction policy:', reactionPolicy);
    
    // Custom threat handling
    if (reactionPolicy === 'CUSTOM') {
        // Show custom UI
        showSecurityWarning(status);
    }
});
```

### Enable Screenshot Prevention

```javascript
AranRASP.enableScreenshotPrevention()
    .then(() => console.log('Screenshot prevention enabled'))
    .catch((error) => console.error(error));
```

### Get Cloud Sync Status

```javascript
AranRASP.getSyncStatus()
    .then((syncStatus) => {
        console.log('Last sync:', new Date(syncStatus.lastSyncTimestamp));
        console.log('Request ID:', syncStatus.currentRequestId);
    });
```

## 📖 API Reference

### `initialize(config)`

Initialize the Aran RASP SDK.

**Parameters:**
- `config.licenseKey` (string) - Your Aran license key
- `config.expectedSignature` (string) - Expected APK signature SHA-256
- `config.environment` (string) - 'DEV', 'UAT', or 'RELEASE'
- `config.backendUrl` (string, optional) - Aran Cloud backend URL

**Returns:** Promise<void>

### `checkEnvironment()`

Perform a comprehensive security scan.

**Returns:** Promise<DeviceStatus>

**DeviceStatus Object:**
```javascript
{
    // Native detections
    isRooted: boolean,
    isFridaDetected: boolean,
    isDebuggerAttached: boolean,
    isEmulator: boolean,
    isHooked: boolean,
    isTampered: boolean,
    isUntrustedInstaller: boolean,
    isDeveloperModeEnabled: boolean,
    isAdbEnabled: boolean,
    
    // Kotlin detections
    isVpnActive: boolean,
    isScreenRecording: boolean,
    hasKeyloggerRisk: boolean,
    hasUntrustedKeyboard: boolean,
    isDeviceLockMissing: boolean,
    hasOverlayAttack: boolean,
    hasMalware: boolean,
    isOnUnsecuredWifi: boolean,
    hasSmsForwarder: boolean,
    hasRemoteAccessApp: boolean,
    
    // Lists
    malwarePackages: string[],
    smsForwarderApps: string[],
    remoteAccessApps: string[],
    
    // Metadata
    deviceFingerprint: string,
    appId: string,
    hasThreat: boolean,
    threatCount: number
}
```

### `setThreatListener(callback)`

Set a callback for threat detection events.

**Parameters:**
- `callback(status, reactionPolicy)` - Function to handle threats

### `enableScreenshotPrevention()`

Enable screenshot and screen recording prevention.

**Returns:** Promise<void>

### `disableScreenshotPrevention()`

Disable screenshot prevention.

**Returns:** Promise<void>

### `getSyncStatus()`

Get cloud configuration sync status.

**Returns:** Promise<SyncStatus>

### `forceSync()`

Force immediate cloud configuration sync.

**Returns:** Promise<void>

### `getDeviceFingerprint()`

Get unique device fingerprint.

**Returns:** Promise<string>

## 🔐 Security Best Practices

1. **Store License Key Securely**: Never hardcode in source code
2. **Verify Signature**: Always provide expected APK signature
3. **Use RELEASE Mode**: In production builds
4. **Enable Screenshot Prevention**: For sensitive screens
5. **Handle Threats Appropriately**: Implement custom threat handlers
6. **Monitor Cloud Sync**: Check sync status regularly

## 🌐 Backend Integration

The plugin automatically connects to Aran Cloud for:
- Dynamic threat intelligence updates
- Malware/SMS forwarder/Remote access app blacklists
- Tenant-specific whitelists
- Reaction policy configuration

## 📱 Platform Support

- ✅ Android 7.0+ (API 24+)
- ✅ iOS 12.0+

## 📄 License

Proprietary - Aran Security Platform

## 🆘 Support

- Email: support@aran.mazhai.org
- Docs: https://docs.aran.mazhai.org
- Dashboard: https://dashboard.aran.mazhai.org
