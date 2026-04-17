# Capacitor Plugin - Aran Security Integration Guide

Complete step-by-step guide for integrating Aran Security into Capacitor/Ionic applications.

---

## 📋 Prerequisites

- Node.js 16+
- Capacitor 5.0+
- Ionic CLI (optional)
- Android Studio
- Xcode (for iOS)

---

## 🚀 Step 1: Install Capacitor Plugin

### Option A: From NPM (Production)

```bash
npm install @aran-security/capacitor-plugin
npx cap sync
```

### Option B: From Local Path (Development)

```bash
npm install /path/to/capacitor-plugin-aran-security
npx cap sync
```

---

## 📦 Step 2: Configure AAR Dependency

### Option A: Using Maven Repository (Recommended)

The plugin is pre-configured to use Maven repository.

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

Check `android/build.gradle` in your Capacitor project contains:

```gradle
allprojects {
    repositories {
        maven {
            url "https://maven.aran.mazhai.org/releases"
        }
    }
}
```

### Option B: Using Local AAR File (Development)

#### 2.1 Build or Obtain AAR

```bash
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease
```

#### 2.2 Copy AAR to Plugin

```bash
# Copy to plugin's libs directory
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   node_modules/@aran-security/capacitor-plugin/android/libs/aran-android-sdk-1.0.0.aar
```

#### 2.3 Update Plugin Configuration

Edit `node_modules/@aran-security/capacitor-plugin/android/build.gradle`:

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

#### 2.4 Sync Capacitor

```bash
npx cap sync android
```

---

## 🔐 Step 3: Get APK Signature

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
keytool -list -v -keystore /path/to/release.keystore \
    -alias your-alias | grep SHA256
```

Copy SHA-256 and remove colons: `A1:B2:C3...` → `A1B2C3...`

---

## 📱 Step 4: Initialize SDK (TypeScript)

### 4.1 Import Plugin

```typescript
import { AranSecurity } from '@aran-security/capacitor-plugin';
```

### 4.2 Initialize in App Component

**Angular (app.component.ts):**

```typescript
import { Component, OnInit } from '@angular/core';
import { Platform } from '@ionic/angular';
import { AranSecurity } from '@aran-security/capacitor-plugin';

@Component({
  selector: 'app-root',
  templateUrl: 'app.component.html'
})
export class AppComponent implements OnInit {
  
  constructor(private platform: Platform) {}
  
  async ngOnInit() {
    await this.platform.ready();
    await this.initializeSecurity();
  }
  
  async initializeSecurity() {
    try {
      await AranSecurity.start({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
        environment: 'RELEASE'
      });
      
      console.log('Aran Security initialized');
      await this.performSecurityCheck();
    } catch (error) {
      console.error('Security initialization failed:', error);
    }
  }
  
  async performSecurityCheck() {
    const status = await AranSecurity.checkEnvironment();
    
    if (status.hasThreat) {
      console.warn(`${status.threatCount} threats detected`);
      this.handleThreats(status);
    }
  }
  
  handleThreats(status: any) {
    if (status.isRooted) {
      alert('Warning: Device is rooted!');
    }
    if (status.fridaDetected) {
      alert('Warning: Frida detected!');
    }
  }
}
```

**React:**

```typescript
import { useEffect } from 'react';
import { AranSecurity } from '@aran-security/capacitor-plugin';

function App() {
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
      
      const status = await AranSecurity.checkEnvironment();
      if (status.hasThreat) {
        console.warn('Threats detected:', status.threatCount);
      }
    } catch (error) {
      console.error('Security error:', error);
    }
  };
  
  return <div>Your App</div>;
}
```

**Vue:**

```typescript
import { onMounted } from 'vue';
import { AranSecurity } from '@aran-security/capacitor-plugin';

export default {
  setup() {
    onMounted(async () => {
      try {
        await AranSecurity.start({
          licenseKey: 'YOUR_LICENSE_KEY',
          expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
          environment: 'RELEASE'
        });
        
        const status = await AranSecurity.checkEnvironment();
        console.log('Security status:', status);
      } catch (error) {
        console.error('Security error:', error);
      }
    });
  }
};
```

---

## 🛡️ Step 5: Implement Security Features

### 5.1 Comprehensive Security Check

```typescript
async checkSecurity() {
  try {
    const status = await AranSecurity.checkEnvironment();
    
    console.log('Device Status:', {
      isRooted: status.isRooted,
      fridaDetected: status.fridaDetected,
      debuggerAttached: status.debuggerAttached,
      emulatorDetected: status.emulatorDetected,
      tampered: status.tampered,
      hasThreat: status.hasThreat,
      threatCount: status.threatCount
    });
    
    return status;
  } catch (error) {
    console.error('Security check failed:', error);
    throw error;
  }
}
```

### 5.2 Set Threat Listener

```typescript
async setupThreatListener() {
  await AranSecurity.setThreatListener((data) => {
    console.log('Threat detected:', data);
    
    if (data.reactionPolicy === 'CUSTOM') {
      this.showSecurityAlert(data.status);
    }
  });
}

showSecurityAlert(status: any) {
  const alert = document.createElement('ion-alert');
  alert.header = 'Security Alert';
  alert.message = `${status.threatCount} security threats detected`;
  alert.buttons = ['OK'];
  
  document.body.appendChild(alert);
  alert.present();
}
```

### 5.3 Screenshot Prevention

```typescript
async enableSecureMode() {
  try {
    await AranSecurity.enableSecureWindow();
    console.log('Secure mode enabled');
  } catch (error) {
    console.error('Failed to enable secure mode:', error);
  }
}

async disableSecureMode() {
  try {
    await AranSecurity.disableSecureWindow();
    console.log('Secure mode disabled');
  } catch (error) {
    console.error('Failed to disable secure mode:', error);
  }
}
```

### 5.4 Generate Hardware-Attested JWT

```typescript
async makeSecureApiCall() {
  try {
    const { sigil } = await AranSecurity.generateSigil();
    
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
}
```

---

## 🔔 Step 6: Ionic-Specific Integration

### 6.1 Create Security Service

```typescript
// security.service.ts
import { Injectable } from '@angular/core';
import { AranSecurity } from '@aran-security/capacitor-plugin';
import { AlertController } from '@ionic/angular';

@Injectable({
  providedIn: 'root'
})
export class SecurityService {
  
  constructor(private alertController: AlertController) {}
  
  async initialize() {
    try {
      await AranSecurity.start({
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_SIGNATURE',
        environment: 'RELEASE'
      });
      
      await this.setupThreatListener();
    } catch (error) {
      console.error('Security initialization failed:', error);
    }
  }
  
  async checkEnvironment() {
    return await AranSecurity.checkEnvironment();
  }
  
  async setupThreatListener() {
    await AranSecurity.setThreatListener(async (data) => {
      if (data.status.hasThreat) {
        await this.showThreatAlert(data.status);
      }
    });
  }
  
  async showThreatAlert(status: any) {
    const alert = await this.alertController.create({
      header: 'Security Warning',
      message: `${status.threatCount} security threats detected`,
      buttons: ['OK']
    });
    
    await alert.present();
  }
  
  async enableSecureMode() {
    await AranSecurity.enableSecureWindow();
  }
  
  async disableSecureMode() {
    await AranSecurity.disableSecureWindow();
  }
}
```

### 6.2 Use in Component

```typescript
import { Component, OnInit } from '@angular/core';
import { SecurityService } from './services/security.service';

@Component({
  selector: 'app-home',
  templateUrl: 'home.page.html'
})
export class HomePage implements OnInit {
  
  securityStatus: any;
  
  constructor(private security: SecurityService) {}
  
  async ngOnInit() {
    this.securityStatus = await this.security.checkEnvironment();
  }
  
  async refreshSecurity() {
    this.securityStatus = await this.security.checkEnvironment();
  }
}
```

---

## 🧪 Step 7: Testing

### 7.1 Run on Device

```bash
# Build and run on Android
npx cap run android

# Build and run on iOS
npx cap run ios
```

### 7.2 Live Reload (Development)

```bash
# Start dev server
ionic serve

# In another terminal, sync and run
npx cap run android -l --external
```

### 7.3 Debug Logs

```bash
# Android logs
adb logcat | grep Aran

# Or use Android Studio Logcat
```

---

## 📦 Step 8: Build for Production

### 8.1 Update Environment

```typescript
// environment.prod.ts
export const environment = {
  production: true,
  aranLicenseKey: 'PROD_LICENSE_KEY',
  aranSignature: 'RELEASE_SIGNATURE_SHA256'
};
```

```typescript
// Use in app
import { environment } from '../environments/environment';

await AranSecurity.start({
  licenseKey: environment.aranLicenseKey,
  expectedSignature: environment.aranSignature,
  environment: 'RELEASE'
});
```

### 8.2 Build Release

```bash
# Build web assets
ionic build --prod

# Sync to native
npx cap sync

# Build Android release
cd android
./gradlew assembleRelease

# Build iOS release (in Xcode)
# Product > Archive
```

---

## 🔧 Step 9: Advanced Configuration

### 9.1 Custom Capacitor Configuration

Edit `capacitor.config.ts`:

```typescript
import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.example.app',
  appName: 'MyApp',
  webDir: 'www',
  plugins: {
    AranSecurity: {
      autoInit: false,  // Manual initialization
      logLevel: 'info'
    }
  }
};

export default config;
```

### 9.2 ProGuard Rules

Create `android/app/proguard-rules.pro`:

```proguard
-keep class org.mazhai.aran.** { *; }
-keepclassmembers class org.mazhai.aran.** { *; }
-keepattributes *Annotation*
```

---

## 🚨 Troubleshooting

### Issue: Plugin Not Found

**Error:** `Plugin AranSecurity does not have web implementation`

**Solution:** This is expected - the plugin only works on native platforms (Android/iOS).

```typescript
import { Capacitor } from '@capacitor/core';

if (Capacitor.isNativePlatform()) {
  await AranSecurity.start({...});
}
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
npx cap sync android
```

### Issue: TypeScript Errors

**Error:** `Cannot find module '@aran-security/capacitor-plugin'`

**Solution:**
```bash
npm install @aran-security/capacitor-plugin
npx cap sync
```

### Issue: Signature Mismatch

**Solution:**
- Debug builds: Use debug keystore signature
- Release builds: Use release keystore signature
- Verify format: No colons, uppercase hex

---

## 📚 API Reference

### Methods

```typescript
// Initialize SDK
start(options: StartOptions): Promise<void>

// Security scan
checkEnvironment(): Promise<DeviceStatus>

// Threat listener
setThreatListener(callback: (data: ThreatEvent) => void): Promise<void>

// Threat handling
handleThreats(options: HandleThreatsOptions): Promise<void>

// Screenshot prevention
enableSecureWindow(): Promise<void>
disableSecureWindow(): Promise<void>

// Cloud sync
getSyncStatus(): Promise<SyncStatus>

// Device fingerprint
getDeviceFingerprint(): Promise<{ fingerprint: string }>

// Clipboard
clearClipboard(): Promise<void>

// Hardware attestation
generateSigil(): Promise<{ sigil: string }>
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
```

---

## ✅ Checklist

- [ ] Installed Capacitor plugin via NPM
- [ ] Configured AAR dependency (Maven or local)
- [ ] Obtained APK signature SHA-256
- [ ] Initialized SDK in app component
- [ ] Implemented security checks
- [ ] Set up threat listener
- [ ] Enabled screenshot prevention
- [ ] Created security service (Ionic)
- [ ] Tested on physical device
- [ ] Configured production environment
- [ ] Built release APK/IPA

---

## 📞 Support

- **Email:** support@aran.mazhai.org
- **Docs:** https://docs.aran.mazhai.org
- **Dashboard:** https://dashboard.aran.mazhai.org
