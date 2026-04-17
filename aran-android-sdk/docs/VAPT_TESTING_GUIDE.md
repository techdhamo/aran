# Aran Secure SDK — VAPT Testing Guide

**Version:** 1.0.0  
**Target Audience:** QA Engineers, Security Testers, Penetration Testers  
**Last Updated:** February 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Test Environment Setup](#test-environment-setup)
3. [Testing Procedures](#testing-procedures)
   - [Root Detection Testing](#1-root-detection-testing)
   - [Frida/DBI Detection Testing](#2-fridadbi-detection-testing)
   - [Emulator Detection Testing](#3-emulator-detection-testing)
   - [Debugger Detection Testing](#4-debugger-detection-testing)
   - [Tamper Detection Testing](#5-tamper-detection-testing)
   - [Proxy/MITM Detection Testing](#6-proxymitm-detection-testing)
   - [Malware/Harmful App Detection Testing](#7-malwareharmful-app-detection-testing)
   - [VPN Detection Testing](#8-vpn-detection-testing)
   - [Screen Recording/Mirroring Testing](#9-screen-recordingmirroring-testing)
   - [Overlay Attack Testing](#10-overlay-attack-testing)
   - [Hooking Framework Detection Testing](#11-hooking-framework-detection-testing)
   - [Developer Mode Detection Testing](#12-developer-mode-detection-testing)
4. [Pentest Simulation Mode](#pentest-simulation-mode)
5. [Expected Results Matrix](#expected-results-matrix)
6. [Reporting](#reporting)

---

## Overview

This guide provides step-by-step instructions for QA engineers to manually trigger and verify each threat detection mechanism in the Aran Secure SDK.

### Prerequisites

- Android device or emulator with SDK installed
- ADB (Android Debug Bridge) installed
- Basic command-line knowledge
- Access to demo app or integrated fintech app

### Testing Approach

Each test follows this structure:

1. **Objective** — What we're testing
2. **Test Steps** — How to trigger the threat
3. **Expected Result** — What the SDK should detect
4. **Detection Mechanisms** — How the SDK detects it (for reference)

---

## Test Environment Setup

### Required Tools

```bash
# Install ADB (if not already installed)
brew install android-platform-tools  # macOS
sudo apt-get install android-tools-adb  # Linux

# Verify ADB
adb version
```

### Test Device Recommendations

| Test Type | Recommended Device |
|-----------|-------------------|
| Root Detection | Physical device with Magisk |
| Frida Detection | Physical device or rooted emulator |
| Emulator Detection | Android Studio AVD, Genymotion, BlueStacks |
| Debugger Detection | Any device with Android Studio |
| Tamper Detection | Any device with apktool |
| Proxy Detection | Any device with Wi-Fi |
| VPN Detection | Any device with VPN app |

---

## Testing Procedures

### 1. Root Detection Testing

**Objective:** Verify the SDK detects rooted devices.

#### Test Steps

**Method 1: Install Magisk (Recommended)**

1. **Download Magisk APK:**
   ```bash
   # Visit https://github.com/topjohnwu/Magisk/releases
   # Download latest Magisk-vXX.X.apk
   ```

2. **Install Magisk:**
   ```bash
   adb install Magisk-v26.1.apk
   ```

3. **Patch boot image and flash** (requires unlocked bootloader):
   - Open Magisk app
   - Tap "Install" → "Select and Patch a File"
   - Select your device's boot.img
   - Flash patched image via fastboot

4. **Reboot device:**
   ```bash
   adb reboot
   ```

**Method 2: Use Pre-Rooted Device**

- Use a device that's already rooted (e.g., test device with SuperSU/Magisk)

**Method 3: Simulation (No Root Required)**

- Use the demo app's **"🧪 Simulate Frida Injection"** button (triggers similar alert)

#### Verification

1. **Run the app** and trigger a security scan:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "isRooted: ${status.isRooted}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `rooted: ⚠ DETECTED`

#### Expected Result

- ✅ `status.isRooted = true`
- ⚠️ If environment is `UAT` or `RELEASE`, app should terminate with alert:
  ```
  Security threat detected.
  
  rooted: true
  ```

#### Detection Mechanisms

The SDK checks 23 file artifacts:
- `/system/xbin/su`
- `/system/bin/su`
- `/sbin/su`
- `/system/app/Superuser.apk`
- `/data/local/tmp/su`
- `/data/local/bin/su`
- And 17 more paths...

Plus:
- Magisk properties: `ro.boot.vbmeta.device_state`, `ro.boot.verifiedbootstate`
- SELinux: Permissive mode check
- Build tags: `test-keys` in `Build.TAGS`
- System properties: `ro.debuggable`, `ro.secure`

---

### 2. Frida/DBI Detection Testing

**Objective:** Verify the SDK detects Frida dynamic instrumentation framework.

#### Test Steps

1. **Download Frida server:**
   ```bash
   # For ARM64 devices
   wget https://github.com/frida/frida/releases/download/16.0.0/frida-server-16.0.0-android-arm64.xz
   unxz frida-server-16.0.0-android-arm64.xz
   ```

2. **Push Frida server to device:**
   ```bash
   adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
   adb shell "chmod 755 /data/local/tmp/frida-server"
   ```

3. **Start Frida server:**
   ```bash
   adb shell "/data/local/tmp/frida-server &"
   ```

4. **Verify Frida is running:**
   ```bash
   frida-ps -U
   ```

5. **Attach Frida to your app:**
   ```bash
   frida -U -f com.yourcompany.fintechapp
   ```

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "fridaDetected: ${status.fridaDetected}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `frida: ⚠ DETECTED`

#### Expected Result

- ✅ `status.fridaDetected = true`
- ⚠️ App should terminate if `killOnFrida = true` (UAT/RELEASE)

#### Detection Mechanisms

- **`/proc/self/maps` scan** for 7 needles:
  - `frida-agent`
  - `frida-gadget`
  - `frida-server`
  - `linjector`
  - `libgadget.so`
  - `libfrida.so`
  - `re.frida.server`
- **Port 27042 scan** (default Frida server port)

---

### 3. Emulator Detection Testing

**Objective:** Verify the SDK detects Android emulators.

#### Test Steps

1. **Run the app on an emulator:**
   - Android Studio AVD
   - Genymotion
   - BlueStacks
   - NoxPlayer
   - MEmu

2. **Launch the app** on the emulator

#### Verification

1. **Check detection:**
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "emulatorDetected: ${status.emulatorDetected}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `emulator: ⚠ DETECTED`

#### Expected Result

- ✅ `status.emulatorDetected = true`
- ⚠️ App should terminate if `killOnEmulator = true` (RELEASE mode only)

#### Detection Mechanisms

**Build.* fields (10 checks):**
- `Build.MANUFACTURER`: "Genymotion", "unknown", "Google"
- `Build.BRAND`: "generic", "google"
- `Build.DEVICE`: "generic", "vbox86p", "goldfish"
- `Build.PRODUCT`: "sdk", "google_sdk", "sdk_gphone"
- `Build.HARDWARE`: "goldfish", "ranchu", "vbox86"
- `Build.MODEL`: "sdk", "Emulator", "Android SDK"

**File artifacts:**
- `/dev/socket/qemud`
- `/dev/qemu_pipe`
- `/system/lib/libc_malloc_debug_qemu.so`

**System properties:**
- `ro.kernel.qemu`
- `ro.hardware.audio.primary`
- `init.svc.qemud`

---

### 4. Debugger Detection Testing

**Objective:** Verify the SDK detects attached debuggers.

#### Test Steps

1. **Attach Android Studio debugger:**
   - Open your project in Android Studio
   - Set a breakpoint in your code
   - Click "Debug" (green bug icon)
   - Wait for debugger to attach

2. **Alternative: Use `jdb`:**
   ```bash
   adb forward tcp:8000 jdwp:$(adb shell ps | grep com.yourcompany.fintechapp | awk '{print $2}')
   jdb -attach localhost:8000
   ```

#### Verification

1. **Check detection:**
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "debuggerAttached: ${status.debuggerAttached}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `debugger: ⚠ DETECTED`

#### Expected Result

- ✅ `status.debuggerAttached = true`
- ⚠️ App should terminate if `killOnDebugger = true` (RELEASE mode)

#### Detection Mechanisms

- **`ptrace(PTRACE_TRACEME)` self-attach check** (C++)
- **`/proc/self/status` TracerPid scan** (C++)
- **`Debug.isDebuggerConnected()` JNI call** (Java → C++)

---

### 5. Tamper Detection Testing

**Objective:** Verify the SDK detects repackaged/modified APKs.

#### Test Steps

1. **Decompile the APK:**
   ```bash
   # Install apktool
   brew install apktool  # macOS
   
   # Decompile
   apktool d your-app.apk -o app-decompiled
   ```

2. **Modify the APK:**
   ```bash
   # Add a tamper marker
   echo "tampered" > app-decompiled/assets/tamper.txt
   ```

3. **Repackage with a different signature:**
   ```bash
   # Rebuild APK
   apktool b app-decompiled -o tampered-app.apk
   
   # Sign with debug keystore (different from production)
   jarsigner -keystore ~/.android/debug.keystore \
     -storepass android -keypass android \
     tampered-app.apk androiddebugkey
   
   # Align
   zipalign -v 4 tampered-app.apk tampered-app-aligned.apk
   ```

4. **Install the tampered APK:**
   ```bash
   adb install tampered-app-aligned.apk
   ```

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "tampered: ${status.tampered}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `tampered: ⚠ DETECTED`

#### Expected Result

- ✅ `status.tampered = true` (signature mismatch)
- ⚠️ App should terminate **immediately** if `killOnTamper = true`

#### Alternative Test (No Repackaging)

Use the demo app's **"🧪 Simulate Tampered Signature"** button

#### Detection Mechanism

- **APK signature SHA-256 verification** via JNI
- Compares runtime signature with `expectedSignatureSha256` parameter

---

### 6. Proxy/MITM Detection Testing

**Objective:** Verify the SDK detects HTTP/HTTPS proxy interception.

#### Test Steps

1. **Install Charles Proxy or Burp Suite** on your computer

2. **Start the proxy:**
   - Charles Proxy: Proxy → Proxy Settings → Port 8888
   - Burp Suite: Proxy → Options → Port 8080

3. **Configure Android device to use proxy:**
   - Settings → Wi-Fi
   - Long-press your network → Modify
   - Advanced → Proxy: Manual
   - Hostname: `192.168.1.100` (your computer's IP)
   - Port: `8888` (Charles) or `8080` (Burp)
   - Save

4. **Install CA certificate** (for HTTPS interception):
   - Charles: Help → SSL Proxying → Install Charles Root Certificate on Mobile
   - Burp: Export CA cert → Install on device

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "proxyDetected: ${status.proxyDetected}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `proxy: ⚠ DETECTED`

#### Expected Result

- ✅ `status.proxyDetected = true`
- ⚠️ App should alert/terminate if `killOnProxy = true`

#### Detection Mechanism

- **JVM system properties check** (C++ → JNI):
  - `http.proxyHost`
  - `https.proxyHost`
  - `socksProxyHost`

---

### 7. Malware/Harmful App Detection Testing

**Objective:** Verify the SDK detects known malicious packages.

#### Test Steps

**Method 1: Install a Blacklisted App**

1. **Install Magisk** (root management app, flagged as potentially harmful):
   ```bash
   adb install Magisk-v26.1.apk
   ```

2. **Or install any blacklisted package** (see Detection Mechanisms below)

**Method 2: Simulation (Recommended)**

- Use the demo app's **"🧪 Simulate Malware Presence"** button
- This will show 2 simulated packages: `com.malware.stealer`, `com.fake.trojan`

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "malwarePackages: ${status.malwarePackages}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for:
     ```
     malware: ⚠ 1 HARMFUL APP(S)
       → com.topjohnwu.magisk
     ```

#### Expected Result

- ✅ `status.malwarePackages = ["com.topjohnwu.magisk"]`
- ⚠️ Alert should show **specific package names** to help user uninstall
- ⚠️ App should terminate if `killOnMalware = true`

#### Detection Mechanism

**Blacklisted Packages (24 total):**

**Root Tools:**
- `com.topjohnwu.magisk`
- `eu.chainfire.supersu`
- `com.noshufou.android.su`
- `com.koushikdutta.superuser`
- `com.thirdparty.superuser`
- `com.yellowes.su`
- `me.phh.superuser`
- `com.kingouser.com`

**Xposed/LSPosed:**
- `de.robv.android.xposed.installer`
- `org.lsposed.manager`
- `io.github.lsposed.manager`
- `com.saurik.substrate`

**Root Cloaking:**
- `com.devadvance.rootcloak`
- `com.devadvance.rootcloakplus`
- `com.ramdroid.appquarantine`
- `com.formyhm.hideroot`

**Malware:**
- `com.metasploit.stage`
- `com.tencent.ig.joker`
- `com.android.provision.confirm`
- `com.android.power.supervisor`
- `com.android.vendinc`
- `com.android.vendinh`

**VPN/Proxy:**
- `com.psiphon3`
- `com.psiphon3.subscription`

---

### 8. VPN Detection Testing

**Objective:** Verify the SDK detects active VPN connections.

#### Test Steps

1. **Install a VPN app:**
   - NordVPN
   - ExpressVPN
   - ProtonVPN
   - Or use Android's built-in VPN (Settings → Network → VPN)

2. **Connect to a VPN server:**
   - Open VPN app
   - Select a server
   - Tap "Connect"
   - Wait for connection to establish

3. **Verify VPN is active:**
   - Look for VPN icon in status bar
   - Or check: Settings → Network → VPN → Status: Connected

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "vpnDetected: ${status.vpnDetected}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `vpn: ⚠ DETECTED`

#### Expected Result

- ✅ `status.vpnDetected = true`
- ⚠️ App should alert/terminate if `killOnVpn = true`

#### Detection Mechanism

- **`ConnectivityManager.getNetworkCapabilities()`** → `TRANSPORT_VPN` check (Kotlin)

---

### 9. Screen Recording/Mirroring Testing

**Objective:** Verify the SDK detects screen recording and prevents screenshots.

#### Test Steps

**Part A: Screen Recording Detection**

1. **Start screen recording:**
   - **Android 11+:** Pull down notification shade → Tap "Screen Record"
   - **ADB:** `adb shell screenrecord /sdcard/test.mp4`

2. **Run the app** while recording

**Part B: Screenshot Prevention**

1. **Apply FLAG_SECURE** in your Activity:
   ```kotlin
   import org.mazhai.aran.util.AranSecureWindow
   
   override fun onCreate(savedInstanceState: Bundle?) {
       super.onCreate(savedInstanceState)
       AranSecureWindow.lock(this)
       setContentView(R.layout.activity_main)
   }
   ```

2. **Try to take a screenshot:**
   - Press Power + Volume Down
   - Or use: `adb shell screencap /sdcard/screenshot.png`

#### Verification

**Screen Recording:**
```kotlin
val status = AranSecure.checkEnvironment()
Log.d("VAPT", "screenRecording: ${status.screenRecording}")
```

**Screenshot Prevention:**
- Screenshot should fail with: **"Can't take screenshot due to security policy"**
- Recent apps screen should show **black thumbnail**

#### Expected Result

- ✅ `status.screenRecording = true` (while recording)
- 🚫 Screenshots blocked when `AranSecureWindow.lock()` is active
- 🚫 Recent apps thumbnail is black

#### Detection Mechanisms

- **Screen Recording:** `DisplayManager.getDisplays()` → checks for virtual displays (Kotlin)
- **Screenshot Prevention:** `WindowManager.LayoutParams.FLAG_SECURE` (Kotlin utility)

---

### 10. Overlay Attack Testing

**Objective:** Verify the SDK detects apps with `SYSTEM_ALERT_WINDOW` permission.

#### Test Steps

1. **Install an app with overlay permission:**
   - Facebook Messenger
   - Twilight (screen dimmer)
   - Any app that "draws over other apps"

2. **Grant overlay permission:**
   - Settings → Apps → Special app access → Display over other apps
   - Find the app → Enable "Allow display over other apps"

3. **Verify permission is granted:**
   ```bash
   adb shell dumpsys window | grep -i overlay
   ```

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "overlayDetected: ${status.overlayDetected}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `overlay: ⚠ DETECTED`

#### Expected Result

- ✅ `status.overlayDetected = true` (if any non-system app has overlay permission)
- ⚠️ App should alert/terminate if `killOnOverlay = true`

#### Detection Mechanism

- **Scans installed apps** for `Settings.canDrawOverlays()` permission (Kotlin)
- **Filters out system apps** (only flags third-party apps)

---

### 11. Hooking Framework Detection Testing

**Objective:** Verify the SDK detects Xposed/LSPosed hooking frameworks.

#### Test Steps

1. **Install Xposed or LSPosed:**
   - Download LSPosed from: https://github.com/LSPosed/LSPosed/releases
   - Install via Magisk module or standalone

2. **Activate a module:**
   - Install any Xposed module (e.g., GravityBox)
   - Enable it in LSPosed Manager
   - Reboot device

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "hooked: ${status.hooked}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for: `hooked: ⚠ DETECTED`

#### Expected Result

- ✅ `status.hooked = true`
- ⚠️ App should terminate if `killOnHook = true` (UAT/RELEASE)

#### Detection Mechanisms

**File artifacts:**
- `/system/framework/XposedBridge.jar`

**`/proc/self/maps` scan for 14 keywords:**
- `XposedBridge`
- `LSPosed`
- `EdXposed`
- `VirtualXposed`
- `TaiChi`
- `SandHook`
- `YAHFA`
- `Pine`
- `libepic.so`
- `libsubstrate.so`
- `libhook.so`
- `libnativehook.so`
- `libdobby.so`
- `libwhale.so`

---

### 12. Developer Mode Detection Testing

**Objective:** Verify the SDK detects developer mode and ADB enabled.

#### Test Steps

1. **Enable Developer Options:**
   - Settings → About Phone
   - Tap "Build Number" 7 times
   - Developer options unlocked

2. **Enable USB Debugging:**
   - Settings → Developer Options
   - Enable "USB debugging"

3. **Connect device via USB:**
   ```bash
   adb devices
   ```

#### Verification

1. **Run the app** and check:
   ```kotlin
   val status = AranSecure.checkEnvironment()
   Log.d("VAPT", "developerMode: ${status.developerMode}")
   Log.d("VAPT", "adbEnabled: ${status.adbEnabled}")
   ```

2. **Check demo app UI:**
   - Tap "Scan Device"
   - Look for:
     ```
     dev_mode: ⚠ DETECTED
     adb: ⚠ DETECTED
     ```

#### Expected Result

- ✅ `status.developerMode = true`
- ✅ `status.adbEnabled = true`
- ⚠️ App should terminate if `killOnDeveloperMode = true` or `killOnAdbEnabled = true`

#### Detection Mechanisms

- **Developer Mode:** `Settings.Secure.getInt("development_settings_enabled")` via JNI (C++)
- **ADB Enabled:** `Settings.Secure.getInt("adb_enabled")` via JNI (C++)

---

## Pentest Simulation Mode

The demo app includes a **Pentest Simulation** feature for testing without real threats.

### How to Use

1. **Launch the demo app**

2. **Tap a simulation button:**
   - 🧪 **Simulate Frida Injection** → Sets `fridaDetected = true`
   - 🧪 **Simulate Malware Presence** → Injects 2 fake packages
   - 🧪 **Simulate Tampered Signature** → Sets `tampered = true`

3. **Tap "Scan Device"** → See simulated threat in UI

4. **Tap "✓ Clear Simulation"** → Reset to real device status

### Benefits

- ✅ Test threat alerts **without rooting/modifying** device
- ✅ Verify alert UI and kill behavior
- ✅ Demo to stakeholders without security risks

---

## Expected Results Matrix

| Test | DEV | UAT | RELEASE |
|------|-----|-----|---------|
| Root Detected | Alert only | Alert + Kill | Silent + Kill |
| Frida Detected | Alert only | Alert + Kill | Silent + Kill |
| Debugger Attached | Alert only | Alert only | Silent + Kill |
| Emulator Detected | Alert only | Alert only | Silent + Kill |
| Hooked | Alert only | Alert + Kill | Silent + Kill |
| Tampered | Alert only | Alert + Kill | Silent + Kill |
| Untrusted Installer | Alert only | Alert + Kill | Silent + Kill |
| Developer Mode | Alert only | Alert + Kill | Silent + Kill |
| ADB Enabled | Alert only | Alert + Kill | Silent + Kill |
| Proxy Detected | Alert only | Alert only | Silent + Telemetry |
| VPN Detected | Alert only | Alert only | Silent + Telemetry |
| Malware Detected | Alert only | Alert only | Silent + Telemetry |

**Legend:**
- **Alert only** — Shows dialog with threat details, app continues
- **Alert + Kill** — Shows dialog, then terminates app on OK
- **Silent + Kill** — No dialog, app terminates immediately
- **Silent + Telemetry** — No dialog, sends telemetry only

---

## Reporting

### Test Report Template

```markdown
# Aran Secure SDK — VAPT Test Report

**Date:** YYYY-MM-DD
**Tester:** [Your Name]
**App Version:** [Version]
**SDK Version:** 1.0.0
**Environment:** [DEV/UAT/RELEASE]

## Test Results

| Test Case | Status | Notes |
|-----------|--------|-------|
| Root Detection | ✅ PASS | Detected Magisk v26.1 |
| Frida Detection | ✅ PASS | Detected frida-server 16.0.0 |
| Emulator Detection | ✅ PASS | Detected Android Studio AVD |
| Debugger Detection | ✅ PASS | Detected Android Studio debugger |
| Tamper Detection | ✅ PASS | Detected repackaged APK |
| Proxy Detection | ✅ PASS | Detected Charles Proxy |
| Malware Detection | ✅ PASS | Detected com.topjohnwu.magisk |
| VPN Detection | ✅ PASS | Detected NordVPN connection |
| Screen Recording | ✅ PASS | Detected screen recording |
| Overlay Detection | ✅ PASS | Detected Facebook Messenger overlay |
| Hooking Detection | ✅ PASS | Detected LSPosed framework |
| Developer Mode | ✅ PASS | Detected USB debugging enabled |

## Issues Found

- None

## Recommendations

- All detections working as expected
- Ready for production deployment
```

### Telemetry Verification

After testing, verify telemetry was sent to backend:

```bash
# Check backend logs for telemetry events
curl http://your-backend:33100/api/v1/telemetry/query?app_id=com.yourcompany.fintechapp
```

---

## Support

For questions about VAPT testing or to report detection issues:

- **Email:** support@mazhai.org
- **Documentation:** https://docs.mazhai.org/aran-secure
- **GitHub Issues:** https://github.com/mazhai/aran-android-sdk/issues

---

**Next Steps:**
- ✅ Complete all 12 test procedures
- 📋 Fill out test report template
- 🔄 Verify telemetry backend integration
- 🚀 Approve for production deployment
