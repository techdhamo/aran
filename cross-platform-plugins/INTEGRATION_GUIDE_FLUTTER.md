# Flutter Plugin - Aran Security Integration Guide

Complete step-by-step guide for integrating Aran Security into Flutter applications.

---

## 📋 Prerequisites

- Flutter 3.0+
- Dart 2.19+
- Android Studio
- Xcode (for iOS)

---

## 🚀 Step 1: Install Flutter Plugin

### Option A: From pub.dev (Production)

Add to `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_aran_security: ^1.0.0
```

Then run:

```bash
flutter pub get
```

### Option B: From Local Path (Development)

Add to `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_aran_security:
    path: /path/to/flutter_aran_security
```

Then run:

```bash
flutter pub get
```

### Option C: From Git Repository

```yaml
dependencies:
  flutter_aran_security:
    git:
      url: https://github.com/aran-security/flutter-aran-security.git
      ref: main
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

Check `android/build.gradle` in your Flutter project contains:

```gradle
allprojects {
    repositories {
        google()
        mavenCentral()
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
# Navigate to plugin directory
cd ~/.pub-cache/hosted/pub.dev/flutter_aran_security-1.0.0/android/libs
# Or for local path: cd /path/to/flutter_aran_security/android/libs

# Copy AAR
cp /path/to/aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   ./aran-android-sdk-1.0.0.aar
```

#### 2.3 Update Plugin Configuration

Edit plugin's `android/build.gradle`:

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

#### 2.4 Clean and Rebuild

```bash
flutter clean
flutter pub get
flutter run
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
keytool -list -v -keystore android/app/upload-keystore.jks \
    -alias upload | grep SHA256
```

Copy SHA-256 and remove colons: `A1:B2:C3...` → `A1B2C3...`

---

## 📱 Step 4: Initialize SDK in Flutter

### 4.1 Import Plugin

```dart
import 'package:flutter_aran_security/flutter_aran_security.dart';
```

### 4.2 Initialize in main.dart

```dart
import 'package:flutter/material.dart';
import 'package:flutter_aran_security/flutter_aran_security.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await initializeSecurity();
  
  runApp(const MyApp());
}

Future<void> initializeSecurity() async {
  try {
    await AranSecurity.start(
      StartOptions(
        licenseKey: 'YOUR_LICENSE_KEY',
        expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
        environment: AranEnvironment.release,
      ),
    );
    
    print('Aran Security initialized successfully');
    await performSecurityCheck();
  } catch (e) {
    print('Security initialization failed: $e');
  }
}

Future<void> performSecurityCheck() async {
  try {
    final status = await AranSecurity.checkEnvironment();
    
    if (status.hasThreat) {
      print('Threats detected: ${status.threatCount}');
      handleThreats(status);
    } else {
      print('Device is secure');
    }
  } catch (e) {
    print('Security check failed: $e');
  }
}

void handleThreats(DeviceStatus status) {
  if (status.isRooted) {
    print('WARNING: Device is rooted!');
  }
  if (status.fridaDetected) {
    print('WARNING: Frida detected!');
  }
  if (status.tampered) {
    print('WARNING: App has been tampered!');
  }
}
```

---

## 🛡️ Step 5: Implement Security Features

### 5.1 Comprehensive Security Check

```dart
Future<DeviceStatus> performSecurityScan() async {
  try {
    final status = await AranSecurity.checkEnvironment();
    
    print('Security Report:');
    print('  Root: ${status.isRooted}');
    print('  Frida: ${status.fridaDetected}');
    print('  Debugger: ${status.debuggerAttached}');
    print('  Emulator: ${status.emulatorDetected}');
    print('  Tampered: ${status.tampered}');
    print('  VPN: ${status.vpnDetected}');
    print('  Screen Recording: ${status.screenRecording}');
    print('  Has Threat: ${status.hasThreat}');
    print('  Threat Count: ${status.threatCount}');
    
    return status;
  } catch (e) {
    print('Security scan failed: $e');
    rethrow;
  }
}
```

### 5.2 Set Up Threat Listener

```dart
import 'dart:async';

class SecurityManager {
  StreamSubscription<ThreatEvent>? _threatSubscription;
  
  void initialize() {
    _threatSubscription = AranSecurity.threatStream.listen(
      (event) {
        print('Threat detected: ${event.status.threatCount}');
        
        if (event.reactionPolicy == 'CUSTOM') {
          _showSecurityAlert(event.status);
        }
      },
      onError: (error) {
        print('Threat listener error: $error');
      },
    );
  }
  
  void _showSecurityAlert(DeviceStatus status) {
    // Show dialog or alert
    print('Security Alert: ${status.threatCount} threats detected');
  }
  
  void dispose() {
    _threatSubscription?.cancel();
  }
}
```

### 5.3 Screenshot Prevention

```dart
Future<void> enableSecureMode() async {
  try {
    await AranSecurity.enableSecureWindow();
    print('Secure mode enabled');
  } catch (e) {
    print('Failed to enable secure mode: $e');
  }
}

Future<void> disableSecureMode() async {
  try {
    await AranSecurity.disableSecureWindow();
    print('Secure mode disabled');
  } catch (e) {
    print('Failed to disable secure mode: $e');
  }
}
```

### 5.4 Generate Hardware-Attested JWT

```dart
import 'package:http/http.dart' as http;

Future<void> makeSecureApiCall() async {
  try {
    final sigil = await AranSecurity.generateSigil();
    
    final response = await http.get(
      Uri.parse('https://api.example.com/secure-endpoint'),
      headers: {
        'X-Aran-Sigil': sigil,
        'Content-Type': 'application/json',
      },
    );
    
    if (response.statusCode == 200) {
      print('API call successful: ${response.body}');
    }
  } catch (e) {
    print('Secure API call failed: $e');
  }
}
```

---

## 🎨 Step 6: Create Security Service

### 6.1 Security Service Class

```dart
// lib/services/security_service.dart
import 'package:flutter_aran_security/flutter_aran_security.dart';
import 'dart:async';

class SecurityService {
  static final SecurityService _instance = SecurityService._internal();
  factory SecurityService() => _instance;
  SecurityService._internal();
  
  bool _initialized = false;
  StreamSubscription<ThreatEvent>? _threatSubscription;
  
  Future<void> initialize({
    required String licenseKey,
    required String expectedSignature,
    required AranEnvironment environment,
  }) async {
    if (_initialized) {
      print('Security service already initialized');
      return;
    }
    
    try {
      await AranSecurity.start(
        StartOptions(
          licenseKey: licenseKey,
          expectedSignature: expectedSignature,
          environment: environment,
        ),
      );
      
      _setupThreatListener();
      _initialized = true;
      print('Security service initialized');
    } catch (e) {
      print('Security initialization failed: $e');
      rethrow;
    }
  }
  
  void _setupThreatListener() {
    _threatSubscription = AranSecurity.threatStream.listen(
      (event) {
        if (event.status.hasThreat) {
          _handleThreat(event.status);
        }
      },
    );
  }
  
  void _handleThreat(DeviceStatus status) {
    print('Security threat detected: ${status.threatCount} threats');
  }
  
  Future<DeviceStatus> checkEnvironment() async {
    return await AranSecurity.checkEnvironment();
  }
  
  Future<void> enableSecureMode() async {
    await AranSecurity.enableSecureWindow();
  }
  
  Future<void> disableSecureMode() async {
    await AranSecurity.disableSecureWindow();
  }
  
  Future<String> generateSigil() async {
    return await AranSecurity.generateSigil();
  }
  
  Future<SyncStatus> getSyncStatus() async {
    return await AranSecurity.getSyncStatus();
  }
  
  void dispose() {
    _threatSubscription?.cancel();
  }
}
```

### 6.2 Use in App

```dart
// main.dart
import 'package:flutter/material.dart';
import 'services/security_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await SecurityService().initialize(
    licenseKey: 'YOUR_LICENSE_KEY',
    expectedSignature: 'YOUR_SIGNATURE',
    environment: AranEnvironment.release,
  );
  
  runApp(const MyApp());
}
```

---

## 🎯 Step 7: UI Integration

### 7.1 Security Status Widget

```dart
import 'package:flutter/material.dart';
import 'package:flutter_aran_security/flutter_aran_security.dart';

class SecurityStatusWidget extends StatefulWidget {
  const SecurityStatusWidget({Key? key}) : super(key: key);
  
  @override
  State<SecurityStatusWidget> createState() => _SecurityStatusWidgetState();
}

class _SecurityStatusWidgetState extends State<SecurityStatusWidget> {
  DeviceStatus? _status;
  bool _loading = false;
  
  @override
  void initState() {
    super.initState();
    _checkSecurity();
  }
  
  Future<void> _checkSecurity() async {
    setState(() => _loading = true);
    
    try {
      final status = await AranSecurity.checkEnvironment();
      setState(() {
        _status = status;
        _loading = false;
      });
    } catch (e) {
      setState(() => _loading = false);
      print('Security check failed: $e');
    }
  }
  
  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const CircularProgressIndicator();
    }
    
    if (_status == null) {
      return const Text('Security status unavailable');
    }
    
    return Column(
      children: [
        ListTile(
          leading: Icon(
            _status!.hasThreat ? Icons.warning : Icons.check_circle,
            color: _status!.hasThreat ? Colors.red : Colors.green,
          ),
          title: Text(
            _status!.hasThreat
                ? '${_status!.threatCount} Threats Detected'
                : 'Device is Secure',
          ),
        ),
        if (_status!.isRooted)
          const ListTile(
            leading: Icon(Icons.error, color: Colors.red),
            title: Text('Device is rooted'),
          ),
        if (_status!.fridaDetected)
          const ListTile(
            leading: Icon(Icons.error, color: Colors.red),
            title: Text('Frida detected'),
          ),
        if (_status!.debuggerAttached)
          const ListTile(
            leading: Icon(Icons.error, color: Colors.red),
            title: Text('Debugger attached'),
          ),
      ],
    );
  }
}
```

---

## 🧪 Step 8: Testing

### 8.1 Run on Device

```bash
# Android
flutter run

# iOS
flutter run

# Specific device
flutter devices
flutter run -d <device-id>
```

### 8.2 Debug Logs

```bash
# View logs
flutter logs

# Or use Android Studio / Xcode logcat
```

### 8.3 Development Environment

```dart
import 'package:flutter/foundation.dart';

final environment = kDebugMode ? AranEnvironment.dev : AranEnvironment.release;
final licenseKey = kDebugMode ? 'DEV_LICENSE' : 'PROD_LICENSE';
final signature = kDebugMode ? 'DEBUG_SIGNATURE' : 'RELEASE_SIGNATURE';

await AranSecurity.start(
  StartOptions(
    licenseKey: licenseKey,
    expectedSignature: signature,
    environment: environment,
  ),
);
```

---

## 📦 Step 9: Build for Production

### 9.1 Environment Configuration

```dart
// lib/config/security_config.dart
import 'package:flutter/foundation.dart';
import 'package:flutter_aran_security/flutter_aran_security.dart';

class SecurityConfig {
  static const String devLicenseKey = 'DEV_LICENSE_KEY';
  static const String prodLicenseKey = 'PROD_LICENSE_KEY';
  
  static const String debugSignature = 'DEBUG_SIGNATURE_SHA256';
  static const String releaseSignature = 'RELEASE_SIGNATURE_SHA256';
  
  static String get licenseKey => kDebugMode ? devLicenseKey : prodLicenseKey;
  static String get signature => kDebugMode ? debugSignature : releaseSignature;
  static AranEnvironment get environment => 
      kDebugMode ? AranEnvironment.dev : AranEnvironment.release;
}
```

### 9.2 Build Android Release

```bash
# Build APK
flutter build apk --release

# Build App Bundle
flutter build appbundle --release

# Output locations:
# build/app/outputs/flutter-apk/app-release.apk
# build/app/outputs/bundle/release/app-release.aab
```

### 9.3 Build iOS Release

```bash
flutter build ios --release

# Then archive in Xcode:
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
-keepattributes InnerClasses
```

Add to `android/app/build.gradle`:

```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

---

## 🚨 Troubleshooting

### Issue: Plugin Not Found

**Error:** `MissingPluginException(No implementation found for method...)`

**Solution:**
```bash
flutter clean
flutter pub get
flutter run
```

### Issue: AAR Not Loading

**Error:** `Could not find org.mazhai.aran:aran-android-sdk:1.0.0`

**Solution:**
1. Verify Maven credentials in `~/.gradle/gradle.properties`
2. Or use local AAR method (Step 2, Option B)
3. Clean and rebuild:
```bash
flutter clean
cd android && ./gradlew clean && cd ..
flutter run
```

### Issue: Platform Exception

**Error:** `PlatformException(NOT_INITIALIZED, AranSecurity not initialized...)`

**Solution:** Ensure `AranSecurity.start()` is called before any other methods:
```dart
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AranSecurity.start(...);  // Must be here
  runApp(MyApp());
}
```

### Issue: Signature Mismatch

**Solution:**
- Debug: Use debug keystore signature
- Release: Use release keystore signature
- Format: No colons, uppercase hex

---

## 📚 API Reference

### Methods

```dart
// Initialize SDK
static Future<void> start(StartOptions options)

// Security scan
static Future<DeviceStatus> checkEnvironment()

// Threat stream
static Stream<ThreatEvent> get threatStream

// Threat handling
static Future<void> handleThreats(DeviceStatus status, ReactionPolicy policy)

// Screenshot prevention
static Future<void> enableSecureWindow()
static Future<void> disableSecureWindow()

// Cloud sync
static Future<SyncStatus> getSyncStatus()

// Device fingerprint
static Future<String> getDeviceFingerprint()

// Clipboard
static Future<void> clearClipboard()

// Hardware attestation
static Future<String> generateSigil()
```

### Models

```dart
class StartOptions {
  final String licenseKey;
  final String expectedSignature;
  final AranEnvironment environment;
  final String? backendUrl;
}

class DeviceStatus {
  final bool isRooted;
  final bool fridaDetected;
  final bool debuggerAttached;
  // ... 19 total threat flags
  final List<String> malwarePackages;
  final String deviceFingerprint;
  final String appId;
  final bool hasThreat;
  final int threatCount;
}

enum AranEnvironment { dev, uat, release }
enum ReactionPolicy { logOnly, warnUser, blockApi, killApp, blockAndReport, custom }
```

---

## ✅ Checklist

- [ ] Added plugin to pubspec.yaml
- [ ] Ran flutter pub get
- [ ] Configured AAR dependency (Maven or local)
- [ ] Obtained APK signature SHA-256
- [ ] Initialized SDK in main()
- [ ] Implemented security checks
- [ ] Set up threat stream listener
- [ ] Enabled screenshot prevention
- [ ] Created security service (optional)
- [ ] Tested on physical device
- [ ] Configured production environment
- [ ] Built release APK/AAB
- [ ] Verified ProGuard rules

---

## 📞 Support

- **Email:** support@aran.mazhai.org
- **Docs:** https://docs.aran.mazhai.org
- **Dashboard:** https://dashboard.aran.mazhai.org
