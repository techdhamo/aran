# Aran Secure SDK — Integration Guide

**Version:** 1.0.0  
**Target Audience:** Fintech Developers (Android & iOS)  
**Last Updated:** February 2026

---

## Table of Contents

### Android
1. [Quick Start (Android)](#quick-start-android)
2. [Manifest Requirements](#manifest-requirements)
3. [Application Class Initialization](#application-class-initialization)
4. [Signature Verification Setup](#signature-verification-setup)

### iOS
5. [Quick Start (iOS)](#quick-start-ios)
6. [Info.plist Requirements](#infoplist-requirements)
7. [AppDelegate Initialization](#appdelegate-initialization)
8. [App Attest & Integrity](#app-attest--integrity)

### Shared
9. [Environment Profile Matrix](#environment-profile-matrix)
10. [Utility Classes](#utility-classes)
11. [Troubleshooting](#troubleshooting)
12. [Support](#support)

---

## Quick Start (Android)

Get started with Aran Secure SDK on Android in 3 steps:

1. **Add permissions** to `AndroidManifest.xml`
2. **Initialize SDK** in `Application.onCreate()`
3. **Configure environment** (DEV / UAT / RELEASE)

**Total integration time:** ~10 minutes

---

## Manifest Requirements

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

### Permission Notes

**`QUERY_ALL_PACKAGES` (Restricted Permission)**

- **Purpose:** Enables malware, SMS forwarding, and remote access app detection
- **Google Play Requirement:** Must declare in privacy policy with justification
- **Justification Example:** *"Security scanning for malware, SMS forwarding apps, and remote access tools to protect financial transactions"*
- **Optional:** If you don't need these detections, omit this permission (SDK will return empty lists)

**Other Permissions**

- `INTERNET` — Required for telemetry reporting to backend
- `ACCESS_NETWORK_STATE` — Required for VPN detection
- `ACCESS_WIFI_STATE` — Required for unsecured Wi-Fi detection

---

## Application Class Initialization

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
            environment = AranEnvironment.RELEASE
        )
    }
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `context` | `Context` | Application context (always `this` in `Application.onCreate()`) |
| `licenseKey` | `String` | Your Aran Secure license key (contact support@mazhai.org) |
| `environment` | `AranEnvironment` | One of `DEV`, `UAT`, or `RELEASE` (see [Environment Profile Matrix](#environment-profile-matrix)) |

> **Note:** APK signature verification is now handled automatically by the native Genesis Anchor layer. No need to pass `expectedSignatureSha256`.

### Don't Have a License Key?

Contact **support@mazhai.org** with:
- Company name
- App package name
- Expected monthly active users
- Deployment timeline

---

## Signature Verification Setup

The SDK verifies your APK signature to prevent repackaging attacks (VAPT finding: Code Tampering).

### Step 1: Extract Your Production Certificate SHA-256

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

### Step 2: Pass the SHA-256 to the SDK

```kotlin
AranSecure.start(
    context = this,
    licenseKey = "YOUR_LICENSE_KEY",
    environment = AranEnvironment.RELEASE
)
```

### What Happens if the Signature Doesn't Match?

- ❌ The SDK sets `DeviceStatus.tampered = true`
- ⚠️ If `SecurityPolicy.killOnTamper = true`, the app terminates immediately
- 📡 Telemetry is sent to your backend with `"tamper_detected": true`

### ⚠️ Critical Warning

**Use your PRODUCTION signing certificate SHA-256, not your debug keystore.**

Debug builds will always show `tampered = true` unless you use the debug certificate hash for DEV environment:

```bash
# Extract debug keystore SHA-256
keytool -list -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -storepass android -keypass android | \
  grep SHA256 | awk '{print $2}' | tr -d ':'
```

---

## Quick Start (iOS)

Get started with Aran Secure SDK on iOS in 3 steps:

1. **Add framework** via Swift Package Manager or embed `Aran.xcframework`
2. **Initialize SDK** in `AppDelegate.application(_:didFinishLaunchingWithOptions:)`
3. **Configure environment** (`.dev` / `.uat` / `.release`)

**Total integration time:** ~10 minutes

---

## Info.plist Requirements

Add the following entries to your `Info.plist`:

```xml
<!-- Aran Secure SDK — Required Entries -->

<!-- Network security for Phantom Channel (QUIC sync) -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.aran.mazhai.org</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>

<!-- URL scheme detection for jailbreak/malicious apps -->
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
    <string>activator</string>
</array>
```

### Entry Notes

- **`LSApplicationQueriesSchemes`** — Required for jailbreak detection via URL scheme canOpenURL checks. iOS limits to 50 schemes per app.
- **`NSAppTransportSecurity`** — The SDK enforces TLS. No insecure connections are made.

---

## AppDelegate Initialization

Initialize the SDK in your `AppDelegate` (or `@main` App struct for SwiftUI):

### UIKit

```swift
import UIKit
import Aran

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {

        // ══════════════════════════════════════════════════════════════
        // Aran Secure SDK — Drop-In Initialization
        // ══════════════════════════════════════════════════════════════
        AranSecure.start(
            licenseKey: "YOUR_LICENSE_KEY_HERE",
            environment: .release
        )

        return true
    }
}
```

### SwiftUI

```swift
import SwiftUI
import Aran

@main
struct YourApp: App {

    init() {
        AranSecure.start(
            licenseKey: "YOUR_LICENSE_KEY_HERE",
            environment: .release
        )
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
```

### Parameters (iOS)

| Parameter | Type | Description |
|-----------|------|-------------|
| `licenseKey` | `String` | Your Aran Secure license key (contact support@mazhai.org) |
| `environment` | `AranEnvironment` | One of `.dev`, `.uat`, or `.release` (see [Environment Profile Matrix](#environment-profile-matrix)) |

> **Note:** iOS does not require a signing certificate hash. App integrity is verified via Apple's DCAppAttestService (App Attest) and the native Genesis Anchor C core.

### What Happens on `start()`

1. **Denies debugger attachment** — ARM64 ptrace syscall (release builds only)
2. **Loads Genesis Anchor** — XOR-chain obfuscated C core with fallback config (AES key, HMAC secret, blinded TLS pins, reaction policy)
3. **Initializes Sigil Engine** — Cryptographic attestation with license key
4. **Registers URLProtocol** — Routes TLS certificate challenges through the C core for zero-knowledge pin verification
5. **Starts Phantom Channel** — QUIC/UDP background sync to mazhai-central for dynamic config updates (iOS 15+)
6. **Wipes Genesis state** — Secrets sealed to Secure Enclave, cleared from RAM
7. **Starts environmental scanning** — Continuous jailbreak, VPN, screen mirroring, time spoofing detection

---

## App Attest & Integrity

The iOS SDK uses Apple's **DCAppAttestService** (iOS 14+) for app integrity verification — no certificate hash needed.

### What It Detects

- **Jailbreak** — 95+ filesystem paths (palera1n, Dopamine, Serotonin, Roothide/KFD, Cydia, Sileo)
- **Frida/Instrumentation** — dylib injection, DYLD_INSERT_LIBRARIES, method swizzling
- **Debugger** — ptrace denial, sysctl P_TRACED flag
- **VPN** — Network interface enumeration (utun/ipsec/ppp)
- **Screen Mirroring** — UIScreen.screens.count monitoring
- **SSL Pinning Bypass** — SecTrust hook detection via ObjC runtime
- **Time Spoofing** — NTP comparison against system clock
- **Location Spoofing** — Mock location provider detection
- **Unsecured Wi-Fi** — Open network SSID pattern matching
- **Passcode Not Set** — LAContext biometric/passcode check

### Screenshot Prevention (iOS)

```swift
// Enable screenshot & screen recording prevention
AranSecure.shared.enableScreenshotPrevention()

// Disable when no longer needed
AranSecure.shared.disableScreenshotPrevention()
```

Uses a hidden `UITextField` with `isSecureTextEntry = true` to block system screenshots and screen recording.

### Threat Scanning

```swift
// Get current device security status
let status = AranSecure.shared.checkEnvironment()

print(status.isJailbroken)       // Bool
print(status.fridaDetected)       // Bool
print(status.debuggerAttached)    // Bool
print(status.vpnActive)           // Bool
print(status.screenMirroring)     // Bool
print(status.deviceFingerprint)   // String — unique device ID
```

### Sigil Attestation (iOS)

```swift
// Generate cryptographic attestation token
let sigil = AranSecure.shared.generateSigil(for: status)
// Send sigil to your backend for server-side verification
```

---

## Environment Profile Matrix

The SDK supports 3 deployment environments with different security policies:

| Environment | Auto Alert | Kill on Root | Kill on Frida | Kill on Debugger | Kill on Emulator | Kill on Tamper | Telemetry | Use Case |
|-------------|------------|--------------|---------------|------------------|------------------|----------------|-----------|----------|
| **DEV**     | ✅ Yes     | ❌ No        | ❌ No         | ❌ No            | ❌ No            | ❌ No          | ✅ Yes    | Local development |
| **UAT**     | ✅ Yes     | ✅ Yes       | ✅ Yes        | ❌ No            | ❌ No            | ✅ Yes         | ✅ Yes    | QA testing |
| **RELEASE** | ❌ No      | ✅ Yes       | ✅ Yes        | ✅ Yes           | ✅ Yes           | ✅ Yes         | ✅ Yes    | Production |

### DEV (Development)

**Android (Kotlin):**
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "DEV_LICENSE",
    environment = AranEnvironment.DEV
)
```

**iOS (Swift):**
```swift
AranSecure.start(licenseKey: "DEV_LICENSE", environment: .dev)
```

**Behavior:**
- ✅ Shows alert dialogs with threat details
- ❌ **Never kills** the app
- 📊 Sends telemetry to backend for monitoring

**Use Case:**
- Local development
- Debugging on rooted devices
- Testing with Frida/debuggers
- Emulator testing

**Example Alert:**
```
Security threat detected.

rooted: true
frida_detected: false
debugger_attached: true
```

---

### UAT (User Acceptance Testing)

**Android (Kotlin):**
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "UAT_LICENSE",
    environment = AranEnvironment.UAT
)
```

**iOS (Swift):**
```swift
AranSecure.start(licenseKey: "UAT_LICENSE", environment: .uat)
```

**Behavior:**
- ✅ Shows alert dialogs
- ⚠️ **Kills app** on root/frida/tamper
- ✅ Allows debuggers (for QA debugging)
- 📊 Sends telemetry to backend

**Use Case:**
- QA testing
- Pre-production validation
- Beta testing
- Internal testing builds

**Kill Triggers:**
- Root detected
- Frida detected
- Tampered signature
- Untrusted installer
- Developer mode enabled
- ADB enabled

---

### RELEASE (Production)

**Android (Kotlin):**
```kotlin
AranSecure.start(
    context = this,
    licenseKey = "PROD_LICENSE",
    environment = AranEnvironment.RELEASE
)
```

**iOS (Swift):**
```swift
AranSecure.start(licenseKey: "PROD_LICENSE", environment: .release)
```

**Behavior:**
- ❌ **Silent mode** (no alerts shown to user)
- ⚠️ **Kills app** on all major threats
- 📡 Sends telemetry only (for security dashboard)

**Use Case:**
- Production builds
- Google Play Store / App Store distribution
- End-user devices

**Kill Triggers (All):**
- Root detected
- Frida detected
- Debugger attached
- Emulator detected
- Hooking framework detected
- Tampered signature
- Untrusted installer
- Developer mode enabled
- ADB enabled
- Environment variable tampering
- Runtime integrity failure

**Why Silent Mode?**
- Prevents attackers from learning detection mechanisms
- Reduces user friction (no scary alerts for legitimate users)
- Telemetry provides security team with actionable intelligence

---

## Utility Classes

The SDK provides 3 utility classes for additional security hardening:

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
- ✅ Sets `WindowManager.LayoutParams.FLAG_SECURE`
- 🚫 Prevents screenshots (shows "Can't take screenshot" error)
- 🚫 Hides content from recent apps screen (shows black thumbnail)
- 🚫 Blocks screen mirroring/casting

**When to use:**
- Login screens
- Account balance screens
- Transaction confirmation screens
- Any screen with sensitive financial data

**To unlock:**
```kotlin
AranSecureWindow.unlock(this)
```

---

### AranCertPinner — SSL Certificate Pinning

**Purpose:** Prevents SSL pinning bypass attacks (MITM with custom CA certificates).

**Usage:**

**Pin a single domain:**
```kotlin
import org.mazhai.aran.util.AranCertPinner

val client = AranCertPinner.pinned(
    "api.yourbank.com",
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
```

**Pin multiple domains:**
```kotlin
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

**Output:**
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

**Best Practices:**
- Pin at least 2 certificates (primary + backup)
- Update pins before certificate expiry
- Test pins in UAT environment first

---

### AranClipboardGuard — Clipboard Protection

**Purpose:** Prevents sensitive data leakage via clipboard.

**Usage:**

**Clear clipboard immediately:**
```kotlin
import org.mazhai.aran.util.AranClipboardGuard

// After user copies sensitive data
AranClipboardGuard.clearNow(context)
```

**Clear clipboard after delay:**
```kotlin
// Clear clipboard after 30 seconds
AranClipboardGuard.clearAfterDelay(context, delayMs = 30_000)
```

**Detect when user copies data:**
```kotlin
AranClipboardGuard.onCopyDetected(context) {
    Log.w("Security", "User copied data to clipboard")
    // Optionally clear it or show a warning
    AranClipboardGuard.clearAfterDelay(context, delayMs = 10_000)
}
```

**When to use:**
- After user copies account number
- After user copies transaction ID
- After user copies OTP/PIN
- Any sensitive data copy operation

---

## Troubleshooting

### Issue: `tampered = true` in debug builds

**Cause:** You're using the production certificate SHA-256 with a debug-signed APK.

**Solution:** Use your debug keystore SHA-256 for DEV environment:
```bash
keytool -list -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -storepass android -keypass android | \
  grep SHA256
```

---

### Issue: `malwarePackages` is always empty

**Cause:** Missing `QUERY_ALL_PACKAGES` permission.

**Solution:** Add to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
```

**Note:** This is a restricted permission on Google Play. You must declare it in your privacy policy.

---

### Issue: App crashes on startup with `IllegalStateException`

**Cause:** `AranSecure.start()` not called before `checkEnvironment()`.

**Solution:** Ensure `start()` is called in `Application.onCreate()`, not in an Activity:

```kotlin
class YourApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AranSecure.start(...)  // ✅ Correct
    }
}
```

**Not this:**
```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AranSecure.start(...)  // ❌ Wrong
    }
}
```

---

### Issue: Telemetry not reaching backend

**Cause:** Backend URL is incorrect or network permission missing.

**Solution:**

1. **Verify `INTERNET` permission** in manifest:
```xml
<uses-permission android:name="android.permission.INTERNET" />
```

2. **Check backend URL** in `TelemetryClient`:
   - Default: `http://10.0.2.2:33100` (for emulator)
   - For physical devices, update to your server's IP

3. **Test backend connectivity:**
```bash
curl -X POST http://your-backend:33100/api/v1/telemetry/ingest \
  -H "Content-Type: application/json" \
  -d '{"device_fingerprint":"test","app_id":"test","is_rooted":false}'
```

---

### Issue: `fridaDetected = false` even with Frida running

**Cause:** Frida is using a custom port or obfuscated library names.

**Solution:** The SDK scans for common Frida artifacts:
- `/proc/self/maps` for `frida-agent`, `frida-gadget`, `libfrida.so`
- Port 27042 (default Frida server port)

Advanced evasion techniques may bypass detection. Consider enabling `killOnDebugger` as a fallback.

---

### Issue: App killed on legitimate devices

**Cause:** False positive detection (e.g., some Samsung devices have `test-keys` in Build.TAGS).

**Solution:**

1. **Check telemetry** to see which flag triggered
2. **Adjust SecurityPolicy** for UAT/RELEASE:
```kotlin
val customPolicy = SecurityPolicy(
    autoAlert = false,
    killOnRoot = true,
    killOnFrida = true,
    killOnDebugger = true,
    killOnEmulator = false,  // Disable if false positives
    killOnHook = true,
    killOnTamper = true
)

AranSecure.start(
    context = this,
    licenseKey = "...",
    environment = AranEnvironment.RELEASE
)
// Note: Custom policies are now managed via the mazhai-central dashboard.
// Contact support@mazhai.org to configure tenant-specific policy overrides.
```

3. **Report false positives** to support@mazhai.org with device model and Android version

---

### Issue (iOS): App crashes on launch with `AranSecure.start()`

**Cause:** Calling `start()` before the app's main window is available.

**Solution:** Ensure `start()` is called in `application(_:didFinishLaunchingWithOptions:)` (UIKit) or the `App.init()` (SwiftUI):

```swift
// UIKit — ✅ Correct
func application(_ application: UIApplication, didFinishLaunchingWithOptions ...) -> Bool {
    AranSecure.start(licenseKey: "...", environment: .release)
    return true
}
```

---

### Issue (iOS): Jailbreak detection returns false on jailbroken device

**Cause:** Newer jailbreaks (Roothide/KFD-based) hide filesystem artifacts.

**Solution:** The SDK checks 95+ paths including palera1n, Dopamine, Serotonin, and Roothide. If detection is still bypassed:
1. Check `status.nativeThreatMask` — the C core bitmask may flag threats that individual fields miss
2. Enable `killOnDebugger` as a fallback (most jailbreaks attach via ptrace)
3. Report the jailbreak tool and iOS version to support@mazhai.org

---

### Issue (iOS): `LSApplicationQueriesSchemes` warning in Xcode

**Cause:** Missing URL schemes in `Info.plist`.

**Solution:** Add the required schemes (see [Info.plist Requirements](#infoplist-requirements)). The SDK needs these to detect jailbreak apps via `canOpenURL`.

---

### Issue (iOS): Phantom Channel not syncing (iOS < 15)

**Cause:** The QUIC-based Phantom Channel requires `NWConnection` with QUIC support (iOS 15+).

**Solution:** On iOS 13–14, the SDK falls back to URLProtocol-based TLS pinning and uses the Genesis Anchor's embedded config. Dynamic config sync is only available on iOS 15+.

---

## Support

For technical support, integration assistance, or to report security vulnerabilities:

- **Email:** support@mazhai.org
- **Documentation:** https://docs.mazhai.org/aran-secure
- **GitHub Issues (Android):** https://github.com/mazhai/aran-android-sdk/issues
- **GitHub Issues (iOS):** https://github.com/mazhai/aran-ios-sdk/issues
- **License Inquiries:** sales@mazhai.org

---

**Next Steps:**
- ✅ Complete integration following this guide (Android & iOS)
- 📋 Review [VAPT Testing Guide](VAPT_TESTING_GUIDE.md) for QA validation
- 🚀 Deploy to production with `AranEnvironment.RELEASE` (Android) or `.release` (iOS)
