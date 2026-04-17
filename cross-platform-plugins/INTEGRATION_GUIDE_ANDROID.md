# Aran Android SDK - Native Integration Guide

Complete step-by-step guide for integrating Aran Security SDK into native Android applications.

---

## 📋 Prerequisites

- Android Studio Arctic Fox or later
- Minimum SDK: API 24 (Android 7.0)
- Target SDK: API 34 (Android 14)
- Kotlin 1.9.0+
- Gradle 7.4+

---

## 🚀 Step 1: Add Aran SDK Dependency

### Option A: From Maven Repository (Recommended for Production)

#### 1.1 Configure Repository

Add to your project's `settings.gradle` or `build.gradle`:

```gradle
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        
        // Aran Security Maven Repository
        maven {
            url "https://maven.aran.mazhai.org/releases"
            credentials {
                username = project.findProperty("aranMavenUsername") ?: System.getenv("ARAN_MAVEN_USERNAME")
                password = project.findProperty("aranMavenPassword") ?: System.getenv("ARAN_MAVEN_PASSWORD")
            }
        }
    }
}
```

#### 1.2 Add Dependency

In your app's `build.gradle`:

```gradle
dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
    
    // Required dependencies
    implementation "org.jetbrains.kotlin:kotlin-stdlib:1.9.0"
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3"
    implementation "com.squareup.okhttp3:okhttp:4.11.0"
}
```

#### 1.3 Configure Credentials

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

### Option B: From Local AAR File (Development/Testing)

#### 1.1 Build AAR

```bash
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease
```

Output: `aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar`

#### 1.2 Copy AAR to Project

```bash
# Create libs directory if it doesn't exist
mkdir -p app/libs

# Copy AAR
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   app/libs/aran-android-sdk-1.0.0.aar
```

#### 1.3 Configure Gradle

In your app's `build.gradle`:

```gradle
repositories {
    flatDir {
        dirs 'libs'
    }
}

dependencies {
    implementation(name: 'aran-android-sdk-1.0.0', ext: 'aar')
    
    // Required dependencies
    implementation "org.jetbrains.kotlin:kotlin-stdlib:1.9.0"
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3"
    implementation "com.squareup.okhttp3:okhttp:4.11.0"
}
```

---

## 🔧 Step 2: Configure Android Manifest

Add required permissions to `AndroidManifest.xml`:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    
    <!-- Required Permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <application
        android:name=".MyApplication"
        android:allowBackup="false"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        
        <!-- Your activities -->
        
    </application>
</manifest>
```

---

## 📱 Step 3: Initialize SDK in Application Class

### 3.1 Create Application Class

Create `MyApplication.kt`:

```kotlin
package com.example.myapp

import android.app.Application
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment

class MyApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize Aran Security SDK
        AranSecure.start(
            context = this,
            licenseKey = "YOUR_LICENSE_KEY",
            expectedSignatureSha256 = "YOUR_APK_SIGNATURE_SHA256",
            environment = AranEnvironment.RELEASE
        )
    }
}
```

### 3.2 Register Application Class

Update `AndroidManifest.xml`:

```xml
<application
    android:name=".MyApplication"
    ...>
```

---

## 🔐 Step 4: Get Your APK Signature

### Method 1: Using Gradle Task

```bash
./gradlew signingReport
```

Look for the SHA-256 signature in the output.

### Method 2: Using keytool

```bash
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
```

For release keystore:

```bash
keytool -list -v -keystore /path/to/release.keystore -alias your-alias
```

Copy the SHA-256 certificate fingerprint (remove colons):

```
Before: A1:B2:C3:D4:E5:F6:...
After:  A1B2C3D4E5F6...
```

---

## 🛡️ Step 5: Perform Security Checks

### 5.1 Basic Security Scan

```kotlin
import org.mazhai.aran.AranSecure

class MainActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Perform security scan
        val status = AranSecure.checkEnvironment()
        
        // Check for threats
        if (status.hasThreat()) {
            Log.w("Security", "Threats detected: ${status.threatCount}")
            
            if (status.isRooted) {
                Log.w("Security", "Device is rooted!")
            }
            
            if (status.fridaDetected) {
                Log.w("Security", "Frida detected!")
            }
            
            if (status.tampered) {
                Log.w("Security", "App has been tampered!")
            }
        }
    }
}
```

### 5.2 Custom Threat Handling

```kotlin
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus

class MainActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize with custom threat listener
        AranSecure.start(
            context = this,
            licenseKey = "YOUR_LICENSE_KEY",
            expectedSignatureSha256 = "YOUR_SIGNATURE",
            environment = AranEnvironment.RELEASE,
            listener = object : AranThreatListener {
                override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
                    runOnUiThread {
                        showSecurityAlert(status)
                    }
                }
            }
        )
    }
    
    private fun showSecurityAlert(status: DeviceStatus) {
        AlertDialog.Builder(this)
            .setTitle("Security Alert")
            .setMessage("${status.threatCount} security threats detected")
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .show()
    }
}
```

---

## 🔒 Step 6: Enable Security Features

### 6.1 Screenshot Prevention

```kotlin
import org.mazhai.aran.util.AranSecureWindow

class SecureActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Enable screenshot prevention
        AranSecureWindow.enable(this)
        
        setContentView(R.layout.activity_secure)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        // Disable when leaving activity
        AranSecureWindow.disable(this)
    }
}
```

### 6.2 Clipboard Protection

```kotlin
import org.mazhai.aran.util.AranClipboardGuard

// Clear clipboard
AranClipboardGuard.clearClipboard(context)

// Detect clipboard access
AranClipboardGuard.onClipboardAccessed {
    Log.w("Security", "Clipboard accessed!")
}
```

### 6.3 SSL Certificate Pinning

```kotlin
import org.mazhai.aran.util.AranCertPinner
import okhttp3.OkHttpClient

val client = OkHttpClient.Builder()
    .certificatePinner(
        AranCertPinner.build {
            add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        }
    )
    .build()
```

---

## 🌐 Step 7: Cloud Integration

### 7.1 Get Sync Status

```kotlin
val lastSync = AranSecure.getLastSyncTimestamp()
val requestId = AranSecure.getCurrentRequestId()

Log.i("Aran", "Last sync: ${Date(lastSync)}")
Log.i("Aran", "Request ID: $requestId")
```

### 7.2 Generate Hardware-Attested JWT (Sigil)

```kotlin
import org.mazhai.aran.security.AranSigilEngine

val sigilEngine = AranSigilEngine(context, "YOUR_LICENSE_KEY")
val status = AranSecure.checkEnvironment()
val sigil = sigilEngine.generateSigil(status)

// Use in API requests
val request = Request.Builder()
    .url("https://api.example.com/secure-endpoint")
    .header("X-Aran-Sigil", sigil)
    .build()
```

---

## 🧪 Step 8: Testing

### 8.1 Development Environment

```kotlin
AranSecure.start(
    context = this,
    licenseKey = "DEV_LICENSE_KEY",
    expectedSignatureSha256 = "DEBUG_SIGNATURE",
    environment = AranEnvironment.DEV  // Minimal enforcement
)
```

### 8.2 UAT Environment

```kotlin
AranSecure.start(
    context = this,
    licenseKey = "UAT_LICENSE_KEY",
    expectedSignatureSha256 = "UAT_SIGNATURE",
    environment = AranEnvironment.UAT  // Moderate enforcement
)
```

### 8.3 Production Environment

```kotlin
AranSecure.start(
    context = this,
    licenseKey = "PROD_LICENSE_KEY",
    expectedSignatureSha256 = "RELEASE_SIGNATURE",
    environment = AranEnvironment.RELEASE  // Full enforcement
)
```

---

## 📊 Step 9: DeviceStatus Reference

```kotlin
data class DeviceStatus(
    // Native C++ detections
    val isRooted: Boolean,              // Root/Magisk detection
    val fridaDetected: Boolean,         // Frida framework
    val debuggerAttached: Boolean,      // Debugger detection
    val emulatorDetected: Boolean,      // Emulator/simulator
    val hooked: Boolean,                // Xposed/Substrate hooks
    val tampered: Boolean,              // APK signature mismatch
    val untrustedInstaller: Boolean,    // Non-Play Store installer
    val developerMode: Boolean,         // Developer options enabled
    val adbEnabled: Boolean,            // ADB debugging enabled
    val envTampering: Boolean,          // LD_PRELOAD injection
    val runtimeIntegrity: Boolean,      // Suspicious .so files
    val proxyDetected: Boolean,         // HTTP/HTTPS proxy
    
    // Kotlin-level detections
    val vpnDetected: Boolean,           // VPN connection
    val screenRecording: Boolean,       // Screen recording active
    val keyloggerRisk: Boolean,         // Accessibility services
    val untrustedKeyboard: Boolean,     // Third-party keyboard
    val deviceLockMissing: Boolean,     // No screen lock
    val overlayDetected: Boolean,       // Overlay attack
    val malwarePackages: List<String>,  // Detected malware
    val unsecuredWifi: Boolean,         // Open WiFi network
    val smsForwarderApps: List<String>, // SMS forwarding apps
    val remoteAccessApps: List<String>, // Remote access apps
    
    // Metadata
    val deviceFingerprint: String,      // Unique device ID
    val appId: String                   // Package name
)
```

---

## 🔧 Step 10: ProGuard Configuration

Add to `proguard-rules.pro`:

```proguard
# Aran Security SDK
-keep class org.mazhai.aran.** { *; }
-keepclassmembers class org.mazhai.aran.** { *; }

# Native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Prevent stripping of security checks
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
```

---

## 🚨 Troubleshooting

### Issue: SDK Not Initializing

**Error:** `AranSecure.init(context, appId) must be called before checkEnvironment()`

**Solution:** Ensure `AranSecure.start()` is called in `Application.onCreate()` before any security checks.

### Issue: Signature Mismatch

**Error:** App shows as tampered even with correct signature

**Solution:** 
1. Verify signature format (no colons, uppercase)
2. Use debug signature for debug builds
3. Use release signature for release builds

### Issue: AAR Not Found

**Error:** `Could not find org.mazhai.aran:aran-android-sdk:1.0.0`

**Solution:**
1. Verify Maven repository URL
2. Check credentials in `gradle.properties`
3. Try `mavenLocal()` for local testing

### Issue: Native Library Not Loaded

**Error:** `java.lang.UnsatisfiedLinkError`

**Solution:** Ensure AAR contains native libraries in `jni/` folder for all ABIs.

---

## 📚 Additional Resources

- **Dashboard:** https://dashboard.aran.mazhai.org
- **Documentation:** https://docs.aran.mazhai.org
- **Support:** support@aran.mazhai.org
- **API Reference:** https://api.aran.mazhai.org/docs

---

## ✅ Checklist

- [ ] Added Aran SDK dependency (Maven or AAR)
- [ ] Configured AndroidManifest.xml permissions
- [ ] Created Application class with SDK initialization
- [ ] Obtained APK signature SHA-256
- [ ] Implemented security checks in activities
- [ ] Enabled screenshot prevention for sensitive screens
- [ ] Configured ProGuard rules
- [ ] Tested in DEV/UAT environments
- [ ] Verified production configuration
- [ ] Integrated cloud sync and Sigil generation
