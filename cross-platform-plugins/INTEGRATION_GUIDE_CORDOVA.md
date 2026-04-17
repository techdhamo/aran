# Cordova Plugin - Aran Security Integration Guide

Complete step-by-step guide for integrating Aran Security into Apache Cordova applications.

---

## 📋 Prerequisites

- Node.js 16+
- Cordova CLI 10.0+
- Android SDK (API 24+)
- Xcode 12+ (for iOS)

---

## 🚀 Step 1: Install Cordova Plugin

### Option A: From NPM (Production)

```bash
cordova plugin add cordova-plugin-aran-security
```

### Option B: From Local Path (Development)

```bash
cordova plugin add /path/to/cordova-plugin-aran-security
```

### Option C: From Git Repository

```bash
cordova plugin add https://github.com/aran-security/cordova-plugin-aran-security.git
```

---

## 📦 Step 2: Configure AAR Dependency

### Option A: Using Maven Repository (Recommended)

The plugin is pre-configured to use Maven repository. No additional configuration needed.

**Verify in your project:**

Check `platforms/android/app/build.gradle` contains:

```gradle
repositories {
    maven {
        url "https://maven.aran.mazhai.org/releases"
    }
}

dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

**Set Maven credentials:**

Create `~/.gradle/gradle.properties`:

```properties
aranMavenUsername=your-username
aranMavenPassword=your-password
```

Or set environment variables:

```bash
export ARAN_MAVEN_USERNAME=your-username
export ARAN_MAVEN_PASSWORD=your-password
```

### Option B: Using Local AAR File (Development)

#### 2.1 Build or Obtain AAR

```bash
# Build from source
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease

# AAR location:
# aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar
```

#### 2.2 Copy AAR to Plugin

```bash
# Create libs directory
mkdir -p plugins/cordova-plugin-aran-security/libs

# Copy AAR
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   plugins/cordova-plugin-aran-security/libs/aran-android-sdk-1.0.0.aar
```

#### 2.3 Update Plugin Configuration

Edit `plugins/cordova-plugin-aran-security/src/android/aran-security.gradle`:

```gradle
repositories {
    flatDir {
        dirs '../libs'  // Point to plugin's libs folder
    }
}

dependencies {
    // Comment out Maven dependency
    // implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
    
    // Uncomment local AAR
    implementation(name: 'aran-android-sdk-1.0.0', ext: 'aar')
}
```

#### 2.4 Rebuild Platform

```bash
cordova platform remove android
cordova platform add android
```

---

## 🔧 Step 3: Configure Android Permissions

Permissions are automatically added by the plugin. Verify in `config.xml`:

```xml
<platform name="android">
    <config-file target="AndroidManifest.xml" parent="/manifest">
        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    </config-file>
</platform>
```

---

## 🔐 Step 4: Get APK Signature

### For Debug Build

```bash
keytool -list -v -keystore ~/.android/debug.keystore \
    -alias androiddebugkey \
    -storepass android \
    -keypass android | grep SHA256
```

### For Release Build

```bash
keytool -list -v -keystore /path/to/release.keystore \
    -alias your-alias | grep SHA256
```

Copy the SHA-256 fingerprint and remove colons:

```
Before: A1:B2:C3:D4:E5:F6:...
After:  A1B2C3D4E5F6...
```

---

## 📱 Step 5: Initialize SDK in Your App

### 5.1 Basic Initialization

In your `www/js/index.js` or main JavaScript file:

```javascript
document.addEventListener('deviceready', onDeviceReady, false);

function onDeviceReady() {
    // Initialize Aran Security
    AranRASP.AranSecurity.initialize({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
        environment: 'RELEASE',  // 'DEV', 'UAT', or 'RELEASE'
        backendUrl: 'https://api.aran.mazhai.org'
    })
    .then(function() {
        console.log('Aran Security initialized successfully');
        performSecurityCheck();
    })
    .catch(function(error) {
        console.error('Aran Security initialization failed:', error);
    });
}
```

### 5.2 With TypeScript

```typescript
import { AranRASP } from 'cordova-plugin-aran-security';

document.addEventListener('deviceready', async () => {
    try {
        await AranRASP.AranSecurity.initialize({
            licenseKey: 'YOUR_LICENSE_KEY',
            expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
            environment: 'RELEASE'
        });
        
        console.log('Aran Security initialized');
        await performSecurityCheck();
    } catch (error) {
        console.error('Initialization failed:', error);
    }
});
```

---

## 🛡️ Step 6: Perform Security Checks

### 6.1 Basic Security Scan

```javascript
function performSecurityCheck() {
    AranRASP.AranSecurity.checkEnvironment()
        .then(function(status) {
            console.log('Security Status:', status);
            
            if (status.hasThreat) {
                console.warn('Threats detected:', status.threatCount);
                handleThreats(status);
            } else {
                console.log('Device is secure');
            }
        })
        .catch(function(error) {
            console.error('Security check failed:', error);
        });
}

function handleThreats(status) {
    if (status.isRooted) {
        alert('Warning: Device is rooted!');
    }
    
    if (status.fridaDetected) {
        alert('Warning: Frida detected!');
    }
    
    if (status.tampered) {
        alert('Warning: App has been tampered!');
    }
}
```

### 6.2 Continuous Monitoring

```javascript
// Check security every 30 seconds
setInterval(function() {
    AranRASP.AranSecurity.checkEnvironment()
        .then(function(status) {
            if (status.hasThreat) {
                handleThreats(status);
            }
        });
}, 30000);
```

---

## 🔔 Step 7: Set Up Threat Listener

```javascript
// Set up threat listener
AranRASP.AranSecurity.setThreatListener(function(data) {
    console.log('Threat detected!', data);
    console.log('Status:', data.status);
    console.log('Reaction Policy:', data.reactionPolicy);
    
    // Custom threat handling
    if (data.reactionPolicy === 'CUSTOM') {
        showCustomSecurityWarning(data.status);
    }
});

function showCustomSecurityWarning(status) {
    var message = 'Security Alert!\n\n';
    message += 'Threats detected: ' + status.threatCount + '\n\n';
    
    if (status.isRooted) message += '• Device is rooted\n';
    if (status.fridaDetected) message += '• Frida detected\n';
    if (status.debuggerAttached) message += '• Debugger attached\n';
    
    navigator.notification.alert(
        message,
        function() { /* callback */ },
        'Security Warning',
        'OK'
    );
}
```

---

## 🔒 Step 8: Enable Security Features

### 8.1 Screenshot Prevention

```javascript
// Enable screenshot prevention
AranRASP.AranSecurity.enableScreenshotPrevention()
    .then(function() {
        console.log('Screenshot prevention enabled');
    })
    .catch(function(error) {
        console.error('Failed to enable screenshot prevention:', error);
    });

// Disable when needed
AranRASP.AranSecurity.disableScreenshotPrevention()
    .then(function() {
        console.log('Screenshot prevention disabled');
    });
```

### 8.2 Get Cloud Sync Status

```javascript
AranRASP.AranSecurity.getSyncStatus()
    .then(function(syncStatus) {
        var lastSync = new Date(syncStatus.lastSyncTimestamp);
        console.log('Last sync:', lastSync.toLocaleString());
        console.log('Request ID:', syncStatus.currentRequestId);
    });
```

### 8.3 Generate Hardware-Attested JWT

```javascript
AranRASP.AranSecurity.generateSigil()
    .then(function(sigil) {
        console.log('Sigil generated:', sigil);
        
        // Use in API requests
        fetch('https://api.example.com/secure-endpoint', {
            method: 'GET',
            headers: {
                'X-Aran-Sigil': sigil,
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => console.log('API Response:', data));
    });
```

---

## 🧪 Step 9: Testing

### 9.1 Test on Device

```bash
# Build and run on Android
cordova build android
cordova run android

# Build and run on iOS
cordova build ios
cordova run ios
```

### 9.2 Debug Mode

```javascript
// Use DEV environment for testing
AranRASP.AranSecurity.initialize({
    licenseKey: 'DEV_LICENSE_KEY',
    expectedSignature: 'DEBUG_SIGNATURE',
    environment: 'DEV'  // Minimal enforcement
})
.then(function() {
    console.log('Running in DEV mode');
});
```

### 9.3 Check Console Logs

```bash
# Android logs
adb logcat | grep Aran

# iOS logs (in Xcode)
# Window > Devices and Simulators > View Device Logs
```

---

## 📦 Step 10: Build for Production

### 10.1 Update Configuration

```javascript
AranRASP.AranSecurity.initialize({
    licenseKey: 'PROD_LICENSE_KEY',
    expectedSignature: 'RELEASE_SIGNATURE_SHA256',
    environment: 'RELEASE'
});
```

### 10.2 Build Release APK

```bash
# Build release
cordova build android --release

# Sign APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
    -keystore /path/to/release.keystore \
    platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk \
    your-alias

# Align APK
zipalign -v 4 \
    platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk \
    platforms/android/app/build/outputs/apk/release/app-release.apk
```

---

## 🔧 Step 11: Advanced Configuration

### 11.1 Custom Build Configuration

Create `build-extras.gradle` in your project root:

```gradle
repositories {
    maven {
        url "https://maven.aran.mazhai.org/releases"
        credentials {
            username project.findProperty("aranMavenUsername")
            password project.findProperty("aranMavenPassword")
        }
    }
}
```

### 11.2 ProGuard Configuration

Create `proguard-custom.txt`:

```proguard
-keep class org.mazhai.aran.** { *; }
-keepclassmembers class org.mazhai.aran.** { *; }
```

Add to `config.xml`:

```xml
<platform name="android">
    <resource-file src="proguard-custom.txt" target="app/proguard-custom.txt" />
</platform>
```

---

## 🚨 Troubleshooting

### Issue: Plugin Not Found

**Error:** `Cannot find module 'cordova-plugin-aran-security'`

**Solution:**
```bash
cordova plugin remove cordova-plugin-aran-security
cordova plugin add cordova-plugin-aran-security
cordova platform remove android
cordova platform add android
```

### Issue: AAR Not Loading

**Error:** `Could not find org.mazhai.aran:aran-android-sdk:1.0.0`

**Solution:**
1. Verify Maven credentials in `~/.gradle/gradle.properties`
2. Or use local AAR file method (Step 2, Option B)
3. Clean and rebuild: `cordova clean && cordova build android`

### Issue: deviceready Not Firing

**Solution:**
```javascript
// Ensure proper event listener
document.addEventListener('deviceready', onDeviceReady, false);

function onDeviceReady() {
    console.log('Device is ready');
    // Initialize Aran Security here
}
```

### Issue: Signature Mismatch

**Solution:**
- Use debug signature for debug builds
- Use release signature for release builds
- Verify signature format (no colons, uppercase)

---

## 📚 API Reference

### Methods

- `initialize(options)` - Initialize SDK
- `checkEnvironment()` - Perform security scan
- `setThreatListener(callback)` - Set threat detection callback
- `enableScreenshotPrevention()` - Enable screenshot blocking
- `disableScreenshotPrevention()` - Disable screenshot blocking
- `getSyncStatus()` - Get cloud sync status
- `getDeviceFingerprint()` - Get device fingerprint
- `generateSigil()` - Generate hardware-attested JWT

### Types

```javascript
// DeviceStatus
{
    isRooted: boolean,
    fridaDetected: boolean,
    debuggerAttached: boolean,
    emulatorDetected: boolean,
    hooked: boolean,
    tampered: boolean,
    // ... 19 total threat flags
    malwarePackages: string[],
    smsForwarderApps: string[],
    remoteAccessApps: string[],
    deviceFingerprint: string,
    appId: string,
    hasThreat: boolean,
    threatCount: number
}
```

---

## ✅ Checklist

- [ ] Installed Cordova plugin
- [ ] Configured AAR dependency (Maven or local)
- [ ] Obtained APK signature SHA-256
- [ ] Initialized SDK in deviceready event
- [ ] Implemented security checks
- [ ] Set up threat listener
- [ ] Enabled screenshot prevention
- [ ] Tested on physical device
- [ ] Configured production build
- [ ] Verified ProGuard rules

---

## 📞 Support

- **Email:** support@aran.mazhai.org
- **Docs:** https://docs.aran.mazhai.org
- **Dashboard:** https://dashboard.aran.mazhai.org
