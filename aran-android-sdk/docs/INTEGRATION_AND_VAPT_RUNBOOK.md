# Aran Secure SDK — Integration & VAPT Runbook

**Version:** 1.0.0  
**Target Audience:** Fintech Android Developers, QA Engineers, Security Testers  
**Last Updated:** February 2026

---

## Table of Contents

1. [Integration Guide](#integration-guide)
   - [Manifest Requirements](#manifest-requirements)
   - [Application Class Initialization](#application-class-initialization)
   - [Signature Verification Setup](#signature-verification-setup)
   - [Environment Profile Matrix](#environment-profile-matrix)
2. [VAPT Testing Guide](#vapt-testing-guide)
   - [Root Detection Testing](#root-detection-testing)
   - [Frida/DBI Detection Testing](#fridadbi-detection-testing)
   - [Emulator Detection Testing](#emulator-detection-testing)
   - [Debugger Detection Testing](#debugger-detection-testing)
   - [Tamper Detection Testing](#tamper-detection-testing)
   - [Proxy/MITM Detection Testing](#proxymitm-detection-testing)
   - [Malware/Harmful App Detection Testing](#malwareharmful-app-detection-testing)
   - [VPN Detection Testing](#vpn-detection-testing)
   - [Screen Recording/Mirroring Testing](#screen-recordingmirroring-testing)
   - [Overlay Attack Testing](#overlay-attack-testing)
3. [Utility Classes](#utility-classes)
4. [Troubleshooting](#troubleshooting)

---

## Integration Guide

### Manifest Requirements

Add the following permissions to your `AndroidManifest.xml`:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.yourcompany.fintechapp">

    <!-- ══════════════════════════════════════════════════════════════ -->
    <!-- Aran Secure SDK — Required Permissions                         -->
    <!-- ══════════════════════════════════════════════════════════════ -->
    
    <!-- Network telemetry -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <!-- Wi-Fi security check (unsecured network detection) -->
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    
    <!-- Malware/SMS forwarder/Remote access app detection -->
    <!-- Required on Android 11+ to scan installed packages -->
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
        tools:ignore="QueryAllPackagesPermission" />

    <application
        android:name=".YourApplication"
        ...>
        ...
    </application>
</manifest>
```

**Important Notes:**
- `QUERY_ALL_PACKAGES` is a restricted permission on Google Play. You **must** declare it in your Play Console privacy policy and provide justification (e.g., "Security scanning for malware, SMS forwarding apps, and remote access tools to protect financial transactions").
- If you do not need malware/SMS/remote access detection, you can omit `QUERY_ALL_PACKAGES`, but the SDK will return empty lists for those signals.

---

### Application Class Initialization

Initialize the SDK in your `Application.onCreate()` method with **exactly 3 lines**:

```kotlin
package com.yourcompany.fintechapp

import android.app.Application
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranSecure

class YourApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // ══════════════════════════════════════════════════════════════
        // Aran Secure SDK — Drop-In Initialization
        // ══════════════════════════════════════════════════════════════
        AranSecure.start(
            context = this,
            licenseKey = "YOUR_LICENSE_KEY_HERE",
            expectedSignatureSha256 = "YOUR_PRODUCTION_SHA256_HERE",
            environment = AranEnvironment.RELEASE
        )
    }
}
```

**Parameters:**
- `context`: Application context (always `this` in `Application.onCreate()`)
- `licenseKey`: Your Aran Secure license key (contact support@mazhai.org)
- `expectedSignatureSha256`: Your production APK signing certificate SHA-256 hash (see next section)
- `environment`: One of `DEV`, `UAT`, or `RELEASE` (see [Environment Profile Matrix](#environment-profile-matrix))

---

### Signature Verification Setup

The SDK verifies your APK signature to prevent repackaging attacks (VAPT finding: Code Tampering).

#### Step 1: Extract Your Production Certificate SHA-256

Run this command on your **production-signed APK**:

```bash
# Extract signing certificate from APK
unzip -p your-app-release.apk META-INF/*.RSA | \
  keytool -printcert | \
  grep "SHA256:" | \
  awk '{print $2}' | \
  tr -d ':'
```

**Example output:**
```
A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456
```

#### Step 2: Pass the SHA-256 to the SDK

```kotlin
AranSecure.start(
    context = this,
    licenseKey = "YOUR_LICENSE_KEY",
    expectedSignatureSha256 = "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456",
    environment = AranEnvironment.RELEASE
)
```

**What happens if the signature doesn't match?**
- The SDK sets `DeviceStatus.tampered = true`
- If `SecurityPolicy.killOnTamper = true`, the app will terminate immediately
- Telemetry is sent to your backend with `"tamper_detected": true`

**⚠️ Critical:** Use your **production** signing certificate SHA-256, not your debug keystore. Debug builds will always show `tampered = true` unless you use the debug certificate hash.

---

### Environment Profile Matrix

The SDK supports 3 deployment environments with different security policies:

| Environment | Auto Alert | Kill on Root | Kill on Frida | Kill on Debugger | Kill on Emulator | Kill on Tamper | Telemetry |
|-------------|------------|--------------|---------------|------------------|------------------|----------------|-----------|
| **DEV**     | ✅ Yes     | ❌ No        | ❌ No         | ❌ No            | ❌ No            | ❌ No          | ✅ Yes    |
| **UAT**     | ✅ Yes     | ✅ Yes       | ✅ Yes        | ❌ No            | ❌ No            | ✅ Yes         | ✅ Yes    |
| **RELEASE** | ❌ No      | ✅ Yes       | ✅ Yes        | ✅ Yes           | ✅ Yes           | ✅ Yes         | ✅ Yes    |

#### DEV (Development)
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "DEV_LICENSE",
    expectedSignatureSha256 = "DEBUG_CERT_SHA256",
    environment = AranEnvironment.DEV
)
```
- **Behavior:** Shows alert dialogs with threat details, but **never kills** the app
- **Use case:** Local development, debugging on rooted devices, testing with Frida/debuggers
- **Telemetry:** Sent to backend for monitoring

#### UAT (User Acceptance Testing)
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "UAT_LICENSE",
    expectedSignatureSha256 = "UAT_CERT_SHA256",
    environment = AranEnvironment.UAT
)
```
- **Behavior:** Shows alert dialogs **and kills** on root/frida/tamper, but allows debuggers
- **Use case:** QA testing, pre-production validation
- **Telemetry:** Sent to backend

#### RELEASE (Production)
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "PROD_LICENSE",
    expectedSignatureSha256 = "PROD_CERT_SHA256",
    environment = AranEnvironment.RELEASE
)
```
- **Behavior:** **Silent mode** (no alerts), kills on all major threats, sends telemetry only
- **Use case:** Production builds distributed to end users
- **Telemetry:** Sent to backend for security monitoring dashboard

---

## VAPT Testing Guide

This section provides step-by-step instructions for QA engineers to manually trigger and verify each threat detection mechanism.

### Root Detection Testing

**Objective:** Verify the SDK detects rooted devices.

**Test Steps:**

1. **Install Magisk** (most common root method):
   - Download Magisk APK from [https://github.com/topjohnwu/Magisk/releases](https://github.com/topjohnwu/Magisk/releases)
   - Install and patch boot image
   - Reboot device

2. **Run the app** and trigger a security scan:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "isRooted: ${status.isRooted}")
   ```

3. **Expected Result:**
   - `status.isRooted = true`
   - If environment is `UAT` or `RELEASE`, app should terminate with alert

**Alternative Test (without rooting):**
- Use the demo app's **Pentest Simulation** feature:
  - Tap "🧪 Simulate Frida Injection" (simulates root-like behavior)
  - Tap "Scan Device"

**Detection Mechanisms:**
- File artifacts: `/system/xbin/su`, `/system/bin/su`, `/sbin/su`, etc. (23 paths)
- Magisk properties: `ro.boot.vbmeta.device_state`, `ro.boot.verifiedbootstate`
- SELinux: Permissive mode check
- Build tags: `test-keys` in `Build.TAGS`

---

### Frida/DBI Detection Testing

**Objective:** Verify the SDK detects Frida dynamic instrumentation.

**Test Steps:**

1. **Install Frida server** on the device:
   ```bash
   # Download frida-server for Android
   wget https://github.com/frida/frida/releases/download/16.0.0/frida-server-16.0.0-android-arm64.xz
   unxz frida-server-16.0.0-android-arm64.xz
   adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```

2. **Attach Frida** to your app:
   ```bash
   frida -U -f com.yourcompany.fintechapp
   ```

3. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "fridaDetected: ${status.fridaDetected}")
   ```

4. **Expected Result:**
   - `status.fridaDetected = true`
   - App should terminate if `killOnFrida = true`

**Detection Mechanisms:**
- `/proc/self/maps` scan for `frida-agent`, `frida-gadget`, `frida-server`, `linjector`, `libgadget.so`, `libfrida.so`, `re.frida.server`
- Port 27042 scan (default Frida server port)

---

### Emulator Detection Testing

**Objective:** Verify the SDK detects Android emulators.

**Test Steps:**

1. **Run the app on an emulator** (Android Studio AVD, Genymotion, BlueStacks, etc.)

2. **Check detection:**
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "emulatorDetected: ${status.emulatorDetected}")
   ```

3. **Expected Result:**
   - `status.emulatorDetected = true`
   - App should terminate if `killOnEmulator = true` (RELEASE mode)

**Detection Mechanisms:**
- `Build.MANUFACTURER`: "Genymotion", "unknown", "Google"
- `Build.BRAND`: "generic", "google"
- `Build.DEVICE`: "generic", "vbox86p", "goldfish"
- `Build.PRODUCT`: "sdk", "google_sdk", "sdk_gphone"
- `Build.HARDWARE`: "goldfish", "ranchu", "vbox86"
- `Build.MODEL`: "sdk", "Emulator", "Android SDK"
- File artifacts: `/dev/socket/qemud`, `/dev/qemu_pipe`, `/system/lib/libc_malloc_debug_qemu.so`
- System properties: `ro.kernel.qemu`, `ro.hardware.audio.primary`

---

### Debugger Detection Testing

**Objective:** Verify the SDK detects attached debuggers.

**Test Steps:**

1. **Attach Android Studio debugger:**
   - Set a breakpoint in your code
   - Click "Debug" (green bug icon)
   - Wait for debugger to attach

2. **Check detection:**
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "debuggerAttached: ${status.debuggerAttached}")
   ```

3. **Expected Result:**
   - `status.debuggerAttached = true`
   - App should terminate if `killOnDebugger = true` (RELEASE mode)

**Detection Mechanisms:**
- `ptrace(PTRACE_TRACEME)` self-attach check
- `/proc/self/status` TracerPid scan
- `Debug.isDebuggerConnected()` JNI call

---

### Tamper Detection Testing

**Objective:** Verify the SDK detects repackaged/modified APKs.

**Test Steps:**

1. **Modify the APK signature:**
   ```bash
   # Decompile APK
   apktool d your-app.apk -o app-decompiled
   
   # Modify something (e.g., add a file)
   echo "tampered" > app-decompiled/assets/tamper.txt
   
   # Repackage with a different signature
   apktool b app-decompiled -o tampered-app.apk
   jarsigner -keystore debug.keystore tampered-app.apk androiddebugkey
   ```

2. **Install the tampered APK:**
   ```bash
   adb install tampered-app.apk
   ```

3. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "tampered: ${status.tampered}")
   ```

4. **Expected Result:**
   - `status.tampered = true` (signature mismatch)
   - App should terminate immediately if `killOnTamper = true`

**Alternative Test:**
- Use the demo app's **"🧪 Simulate Tampered Signature"** button

---

### Proxy/MITM Detection Testing

**Objective:** Verify the SDK detects HTTP/HTTPS proxy interception.

**Test Steps:**

1. **Install Charles Proxy or Burp Suite** on your computer

2. **Configure Android device to use proxy:**
   - Settings → Wi-Fi → Long-press network → Modify → Advanced → Proxy: Manual
   - Hostname: `192.168.1.100` (your computer's IP)
   - Port: `8888` (Charles default)

3. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "proxyDetected: ${status.proxyDetected}")
   ```

4. **Expected Result:**
   - `status.proxyDetected = true`
   - App should alert/terminate if `killOnProxy = true`

**Detection Mechanisms:**
- JVM system properties: `http.proxyHost`, `https.proxyHost`, `socksProxyHost`

---

### Malware/Harmful App Detection Testing

**Objective:** Verify the SDK detects known malicious packages.

**Test Steps:**

1. **Install a test malware package** (use a harmless test APK with a blacklisted package name):
   ```bash
   # Create a dummy APK with package name "com.topjohnwu.magisk"
   # (This is a root management app, flagged as potentially harmful)
   ```

2. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "malwarePackages: ${status.malwarePackages}")
   ```

3. **Expected Result:**
   - `status.malwarePackages = ["com.topjohnwu.magisk"]`
   - Alert should show: **"malware_detected: 1 harmful app(s)"** with package name listed

**Alternative Test:**
- Use the demo app's **"🧪 Simulate Malware Presence"** button
- This will show 2 simulated packages: `com.malware.stealer`, `com.fake.trojan`

**Blacklisted Packages (24 total):**
- Root tools: `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.noshufou.android.su`
- Xposed/LSPosed: `de.robv.android.xposed.installer`, `org.lsposed.manager`
- Malware: `com.metasploit.stage`, `com.tencent.ig.joker`
- Root cloaking: `com.devadvance.rootcloak`, `com.formyhm.hideroot`

---

### VPN Detection Testing

**Objective:** Verify the SDK detects active VPN connections.

**Test Steps:**

1. **Enable VPN** on the device:
   - Install any VPN app (e.g., NordVPN, ExpressVPN, or Android's built-in VPN)
   - Connect to a VPN server

2. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "vpnDetected: ${status.vpnDetected}")
   ```

3. **Expected Result:**
   - `status.vpnDetected = true`
   - App should alert/terminate if `killOnVpn = true`

**Detection Mechanism:**
- `ConnectivityManager.getNetworkCapabilities()` → `TRANSPORT_VPN` check

---

### Screen Recording/Mirroring Testing

**Objective:** Verify the SDK detects screen recording and prevents screenshots.

**Test Steps:**

1. **Start screen recording:**
   - Pull down notification shade → Tap "Screen Record"
   - Or use `adb shell screenrecord /sdcard/test.mp4`

2. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "screenRecording: ${status.screenRecording}")
   ```

3. **Expected Result:**
   - `status.screenRecording = true`

4. **Test screenshot prevention:**
   - Use `AranSecureWindow.lock(activity)` in your Activity
   - Try to take a screenshot (Power + Volume Down)
   - **Expected:** Screenshot should fail with "Can't take screenshot due to security policy"

**Detection Mechanism:**
- `DisplayManager.getDisplays()` → checks for virtual displays (screen recording creates a virtual display)

---

### Overlay Attack Testing

**Objective:** Verify the SDK detects apps with `SYSTEM_ALERT_WINDOW` permission.

**Test Steps:**

1. **Install an app with overlay permission:**
   - Install Facebook Messenger, Twilight, or any app that draws over other apps
   - Grant "Display over other apps" permission

2. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "overlayDetected: ${status.overlayDetected}")
   ```

3. **Expected Result:**
   - `status.overlayDetected = true` (if any non-system app has overlay permission)

**Detection Mechanism:**
- Scans installed apps for `Settings.canDrawOverlays()` permission
- Filters out system apps (only flags third-party apps)

---

## Utility Classes

### AranSecureWindow — Screenshot & Recent App Protection

**Purpose:** Prevents screenshots, screen recording thumbnails, and recent app exposure.

**Usage:**
```kotlin
import org.mazhai.aran.util.AranSecureWindow

class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Apply FLAG_SECURE to prevent screenshots/recents
        AranSecureWindow.lock(this)
        
        setContentView(R.layout.activity_secure)
    }
}
```

**What it does:**
- Sets `WindowManager.LayoutParams.FLAG_SECURE`
- Prevents screenshots (shows "Can't take screenshot" error)
- Hides content from recent apps screen (shows black thumbnail)
- Blocks screen mirroring/casting

---

### AranCertPinner — SSL Certificate Pinning

**Purpose:** Prevents SSL pinning bypass attacks (MITM with custom CA certificates).

**Usage:**
```kotlin
import org.mazhai.aran.util.AranCertPinner

// Pin a single domain
val client = AranCertPinner.pinned(
    "api.yourbank.com",
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// Pin multiple domains
val pinner = AranCertPinner.pinner(
    "api.yourbank.com" to listOf(
        "sha256/PRIMARY_CERT_HASH",
        "sha256/BACKUP_CERT_HASH"
    ),
    "cdn.yourbank.com" to listOf(
        "sha256/CDN_CERT_HASH"
    )
)

val client = OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build()
```

**How to get SHA-256 pin:**
```bash
openssl s_client -connect api.yourbank.com:443 | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl enc -base64
```

---

### AranClipboardGuard — Clipboard Protection

**Purpose:** Prevents sensitive data leakage via clipboard.

**Usage:**
```kotlin
import org.mazhai.aran.util.AranClipboardGuard

// Clear clipboard immediately
AranClipboardGuard.clearNow(context)

// Clear clipboard after 30 seconds
AranClipboardGuard.clearAfterDelay(context, delayMs = 30_000)

// Detect when user copies data
AranClipboardGuard.onCopyDetected(context) {
    Log.w("Security", "User copied data to clipboard")
    // Optionally clear it or show a warning
}
```

---

## Troubleshooting

### Issue: `tampered = true` in debug builds

**Cause:** You're using the production certificate SHA-256 with a debug-signed APK.

**Solution:** Use your debug keystore SHA-256 for DEV environment:
```bash
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android | grep SHA256
```

---

### Issue: `malwarePackages` is always empty

**Cause:** Missing `QUERY_ALL_PACKAGES` permission.

**Solution:** Add to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
```

---

### Issue: App crashes on startup with `IllegalStateException`

**Cause:** `AranSecure.start()` not called before `checkEnvironment()`.

**Solution:** Ensure `start()` is called in `Application.onCreate()`, not in an Activity.

---

### Issue: Telemetry not reaching backend

**Cause:** Backend URL is incorrect or network permission missing.

**Solution:**
1. Verify `INTERNET` permission in manifest
2. Check backend URL in `TelemetryClient` (default: `http://10.0.2.2:33100` for emulator)
3. For physical devices, update to your server's IP

---

### Issue: `fridaDetected = false` even with Frida running

**Cause:** Frida is using a custom port or obfuscated library names.

**Solution:** The SDK scans for common Frida artifacts. Advanced evasion techniques may bypass detection. Consider enabling `killOnDebugger` as a fallback.

---

## Support

For technical support, integration assistance, or to report security vulnerabilities:

- **Email:** support@mazhai.org
- **Documentation:** https://docs.mazhai.org/aran-secure
- **GitHub Issues:** https://github.com/mazhai/aran-android-sdk/issues

---

**End of Runbook**
