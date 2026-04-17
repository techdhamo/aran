# React Native - Aran Security Integration Guide

Complete step-by-step guide for integrating Aran Security into React Native applications.

---

## 📋 Prerequisites

- Node.js 16+
- React Native 0.70+
- React Native CLI or Expo (bare workflow)
- Android Studio
- Xcode (for iOS)

---

## 🚀 Step 1: Install React Native Module

### Option A: From NPM (Production)

```bash
npm install react-native-aran-security
# or
yarn add react-native-aran-security
```

### Option B: From Local Path (Development)

```bash
npm install /path/to/react-native-aran-security
# or
yarn add file:/path/to/react-native-aran-security
```

### 1.1 Link Native Module (React Native < 0.60)

```bash
react-native link react-native-aran-security
```

For React Native 0.60+, autolinking handles this automatically.

---

## 📦 Step 2: Configure AAR Dependency

### Option A: Using Maven Repository (Recommended)

The module is pre-configured to use Maven repository.

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

**Verify configuration:**

Check `node_modules/react-native-aran-security/android/build.gradle` contains:

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

### Option B: Using Local AAR File (Development)

#### 2.1 Build or Obtain AAR

```bash
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease
```

#### 2.2 Copy AAR to Module

```bash
# Create libs directory
mkdir -p node_modules/react-native-aran-security/android/libs

# Copy AAR
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   node_modules/react-native-aran-security/android/libs/aran-android-sdk-1.0.0.aar
```

#### 2.3 Update Module Configuration

Edit `node_modules/react-native-aran-security/android/build.gradle`:

```gradle
repositories {
    flatDir {
        dirs 'libs'
    }
}

dependencies {
    // Comment out Maven dependency
    // implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
    
    // Uncomment local AAR
    implementation(name: 'aran-android-sdk-1.0.0', ext: 'aar')
}
```

#### 2.4 Rebuild

```bash
cd android
./gradlew clean
cd ..
npx react-native run-android
```

---

## 🔧 Step 3: Configure Android Project

### 3.1 Update settings.gradle

Ensure `android/settings.gradle` includes:

```gradle
include ':react-native-aran-security'
project(':react-native-aran-security').projectDir = new File(rootProject.projectDir, '../node_modules/react-native-aran-security/android')
```

### 3.2 Add to MainApplication.java (if not auto-linked)

```java
import org.mazhai.aran.reactnative.AranSecurityPackage;

@Override
protected List<ReactPackage> getPackages() {
    return Arrays.<ReactPackage>asList(
        new MainReactPackage(),
        new AranSecurityPackage()  // Add this
    );
}
```

---

## 🔐 Step 4: Get APK Signature

### For Debug Build

```bash
cd android
./gradlew signingReport
```

Or using keytool:

```bash
keytool -list -v -keystore ~/.android/debug.keystore \
    -alias androiddebugkey \
    -storepass android \
    -keypass android | grep SHA256
```

### For Release Build

```bash
keytool -list -v -keystore android/app/release.keystore \
    -alias your-alias | grep SHA256
```

Copy SHA-256 and remove colons: `A1:B2:C3...` → `A1B2C3...`

---

## 📱 Step 5: Initialize SDK

### 5.1 TypeScript Setup

```typescript
// App.tsx
import React, { useEffect } from 'react';
import { SafeAreaView, Text, Alert } from 'react-native';
import AranSecurity from 'react-native-aran-security';

const App = () => {
  useEffect(() => {
    initializeSecurity();
  }, []);

  const initializeSecurity = async () => {
    try {
      await AranSecurity.start({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
        environment: 'RELEASE'
      });

      console.log('Aran Security initialized');
      await checkSecurity();
    } catch (error) {
      console.error('Security initialization failed:', error);
    }
  };

  const checkSecurity = async () => {
    try {
      const status = await AranSecurity.checkEnvironment();
      
      if (status.hasThreat) {
        console.warn(`${status.threatCount} threats detected`);
        handleThreats(status);
      }
    } catch (error) {
      console.error('Security check failed:', error);
    }
  };

  const handleThreats = (status: any) => {
    if (status.isRooted) {
      Alert.alert('Security Warning', 'Device is rooted!');
    }
    if (status.fridaDetected) {
      Alert.alert('Security Warning', 'Frida detected!');
    }
    if (status.tampered) {
      Alert.alert('Security Warning', 'App has been tampered!');
    }
  };

  return (
    <SafeAreaView>
      <Text>Aran Security Demo</Text>
    </SafeAreaView>
  );
};

export default App;
```

### 5.2 JavaScript Setup

```javascript
// App.js
import React, { useEffect } from 'react';
import { SafeAreaView, Text, Alert } from 'react-native';
import AranSecurity from 'react-native-aran-security';

const App = () => {
  useEffect(() => {
    initializeSecurity();
  }, []);

  const initializeSecurity = async () => {
    try {
      await AranSecurity.start({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_SIGNATURE',
        environment: 'RELEASE'
      });

      const status = await AranSecurity.checkEnvironment();
      console.log('Security Status:', status);
    } catch (error) {
      console.error('Security error:', error);
    }
  };

  return (
    <SafeAreaView>
      <Text>My App</Text>
    </SafeAreaView>
  );
};

export default App;
```

---

## 🛡️ Step 6: Implement Security Features

### 6.1 Comprehensive Security Check

```typescript
const performSecurityScan = async () => {
  try {
    const status = await AranSecurity.checkEnvironment();
    
    console.log('Security Report:', {
      isRooted: status.isRooted,
      fridaDetected: status.fridaDetected,
      debuggerAttached: status.debuggerAttached,
      emulatorDetected: status.emulatorDetected,
      tampered: status.tampered,
      vpnDetected: status.vpnDetected,
      screenRecording: status.screenRecording,
      hasThreat: status.hasThreat,
      threatCount: status.threatCount
    });
    
    return status;
  } catch (error) {
    console.error('Security scan failed:', error);
    throw error;
  }
};
```

### 6.2 Set Up Threat Listener

```typescript
useEffect(() => {
  const removeListener = AranSecurity.addThreatListener((event) => {
    console.log('Threat detected:', event);
    
    if (event.reactionPolicy === 'CUSTOM') {
      showSecurityAlert(event.status);
    }
  });

  return () => {
    removeListener(); // Cleanup on unmount
  };
}, []);

const showSecurityAlert = (status: any) => {
  Alert.alert(
    'Security Alert',
    `${status.threatCount} security threats detected`,
    [{ text: 'OK' }]
  );
};
```

### 6.3 Screenshot Prevention

```typescript
const enableSecureMode = async () => {
  try {
    await AranSecurity.enableSecureWindow();
    console.log('Secure mode enabled');
  } catch (error) {
    console.error('Failed to enable secure mode:', error);
  }
};

const disableSecureMode = async () => {
  try {
    await AranSecurity.disableSecureWindow();
    console.log('Secure mode disabled');
  } catch (error) {
    console.error('Failed to disable secure mode:', error);
  }
};
```

### 6.4 Generate Hardware-Attested JWT

```typescript
const makeSecureApiCall = async () => {
  try {
    const sigil = await AranSecurity.generateSigil();
    
    const response = await fetch('https://api.example.com/secure', {
      method: 'GET',
      headers: {
        'X-Aran-Sigil': sigil,
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Secure API call failed:', error);
    throw error;
  }
};
```

---

## 🎨 Step 7: Create Security Service (Advanced)

### 7.1 Security Service

```typescript
// services/SecurityService.ts
import AranSecurity from 'react-native-aran-security';
import { Alert } from 'react-native';

class SecurityService {
  private initialized = false;
  private threatListener: (() => void) | null = null;

  async initialize(config: {
    licenseKey: string;
    expectedSignature: string;
    environment: 'DEV' | 'UAT' | 'RELEASE';
  }) {
    if (this.initialized) {
      console.warn('Security service already initialized');
      return;
    }

    try {
      await AranSecurity.start(config);
      this.initialized = true;
      this.setupThreatListener();
      console.log('Security service initialized');
    } catch (error) {
      console.error('Security initialization failed:', error);
      throw error;
    }
  }

  private setupThreatListener() {
    this.threatListener = AranSecurity.addThreatListener((event) => {
      if (event.status.hasThreat) {
        this.handleThreat(event.status);
      }
    });
  }

  private handleThreat(status: any) {
    Alert.alert(
      'Security Warning',
      `${status.threatCount} security threats detected`,
      [{ text: 'OK' }]
    );
  }

  async checkEnvironment() {
    return await AranSecurity.checkEnvironment();
  }

  async enableSecureMode() {
    await AranSecurity.enableSecureWindow();
  }

  async disableSecureMode() {
    await AranSecurity.disableSecureWindow();
  }

  async generateSigil() {
    return await AranSecurity.generateSigil();
  }

  cleanup() {
    if (this.threatListener) {
      this.threatListener();
      this.threatListener = null;
    }
  }
}

export default new SecurityService();
```

### 7.2 Use in App

```typescript
// App.tsx
import React, { useEffect } from 'react';
import SecurityService from './services/SecurityService';

const App = () => {
  useEffect(() => {
    SecurityService.initialize({
      licenseKey: 'YOUR_LICENSE_KEY',
      expectedSignature: 'YOUR_SIGNATURE',
      environment: 'RELEASE'
    });

    return () => {
      SecurityService.cleanup();
    };
  }, []);

  return <YourApp />;
};
```

---

## 🧪 Step 8: Testing

### 8.1 Run on Device

```bash
# Android
npx react-native run-android

# iOS
npx react-native run-ios
```

### 8.2 Debug Logs

```bash
# Android logs
npx react-native log-android

# iOS logs
npx react-native log-ios
```

### 8.3 Development Environment

```typescript
const isDev = __DEV__;

await AranSecurity.start({
  licenseKey: isDev ? 'DEV_LICENSE' : 'PROD_LICENSE',
  expectedSignature: isDev ? 'DEBUG_SIGNATURE' : 'RELEASE_SIGNATURE',
  environment: isDev ? 'DEV' : 'RELEASE'
});
```

---

## 📦 Step 9: Build for Production

### 9.1 Environment Configuration

```typescript
// config.ts
export const Config = {
  dev: {
    licenseKey: 'DEV_LICENSE_KEY',
    signature: 'DEBUG_SIGNATURE',
    environment: 'DEV' as const
  },
  prod: {
    licenseKey: 'PROD_LICENSE_KEY',
    signature: 'RELEASE_SIGNATURE',
    environment: 'RELEASE' as const
  }
};

// Use in app
import { Config } from './config';

const config = __DEV__ ? Config.dev : Config.prod;
await AranSecurity.start(config);
```

### 9.2 Build Android Release

```bash
cd android
./gradlew assembleRelease

# APK location:
# android/app/build/outputs/apk/release/app-release.apk
```

### 9.3 Build iOS Release

```bash
# In Xcode
# Product > Archive
```

---

## 🔧 Step 10: Advanced Configuration

### 10.1 ProGuard Rules

Create `android/app/proguard-rules.pro`:

```proguard
-keep class org.mazhai.aran.** { *; }
-keepclassmembers class org.mazhai.aran.** { *; }
-keepattributes *Annotation*
-keepattributes Signature
```

### 10.2 Gradle Configuration

Edit `android/app/build.gradle`:

```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

---

## 🚨 Troubleshooting

### Issue: Module Not Found

**Error:** `Unable to resolve module 'react-native-aran-security'`

**Solution:**
```bash
# Clear cache
npx react-native start --reset-cache

# Reinstall
rm -rf node_modules
npm install
cd android && ./gradlew clean && cd ..
npx react-native run-android
```

### Issue: Native Module Not Linked

**Error:** `null is not an object (evaluating 'AranSecurity.start')`

**Solution:**
```bash
# For React Native < 0.60
react-native link react-native-aran-security

# For React Native >= 0.60
cd android && ./gradlew clean && cd ..
npx react-native run-android
```

### Issue: AAR Not Loading

**Error:** `Could not find org.mazhai.aran:aran-android-sdk:1.0.0`

**Solution:**
1. Verify Maven credentials in `~/.gradle/gradle.properties`
2. Or use local AAR method (Step 2, Option B)
3. Clean and rebuild:
```bash
cd android
./gradlew clean
cd ..
npx react-native run-android
```

### Issue: Signature Mismatch

**Solution:**
- Debug: Use debug keystore signature
- Release: Use release keystore signature
- Format: Remove colons, uppercase hex

---

## 📚 API Reference

### Methods

```typescript
// Initialize SDK
start(options: StartOptions): Promise<void>

// Security scan
checkEnvironment(): Promise<DeviceStatus>

// Threat listener
addThreatListener(callback: (event: ThreatEvent) => void): () => void

// Threat handling
handleThreats(status: DeviceStatus, reactionPolicy: ReactionPolicy): Promise<void>

// Screenshot prevention
enableSecureWindow(): Promise<void>
disableSecureWindow(): Promise<void>

// Cloud sync
getSyncStatus(): Promise<SyncStatus>

// Device fingerprint
getDeviceFingerprint(): Promise<string>

// Clipboard
clearClipboard(): Promise<void>

// Hardware attestation
generateSigil(): Promise<string>
```

### Types

```typescript
interface StartOptions {
  licenseKey: string;
  expectedSignature: string;
  environment: 'DEV' | 'UAT' | 'RELEASE';
  backendUrl?: string;
}

interface DeviceStatus {
  isRooted: boolean;
  fridaDetected: boolean;
  debuggerAttached: boolean;
  emulatorDetected: boolean;
  hooked: boolean;
  tampered: boolean;
  // ... 19 total threat flags
  malwarePackages: string[];
  smsForwarderApps: string[];
  remoteAccessApps: string[];
  deviceFingerprint: string;
  appId: string;
  hasThreat: boolean;
  threatCount: number;
}

interface ThreatEvent {
  status: DeviceStatus;
  reactionPolicy: string;
}

type ReactionPolicy = 
  | 'LOG_ONLY'
  | 'WARN_USER'
  | 'BLOCK_API'
  | 'KILL_APP'
  | 'BLOCK_AND_REPORT'
  | 'CUSTOM';
```

---

## ✅ Checklist

- [ ] Installed React Native module via NPM
- [ ] Configured AAR dependency (Maven or local)
- [ ] Obtained APK signature SHA-256
- [ ] Initialized SDK in App component
- [ ] Implemented security checks
- [ ] Set up threat listener with cleanup
- [ ] Enabled screenshot prevention
- [ ] Created security service (optional)
- [ ] Tested on physical device
- [ ] Configured production environment
- [ ] Built release APK/IPA
- [ ] Verified ProGuard rules

---

## 📞 Support

- **Email:** support@aran.mazhai.org
- **Docs:** https://docs.aran.mazhai.org
- **Dashboard:** https://dashboard.aran.mazhai.org
