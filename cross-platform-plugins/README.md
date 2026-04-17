# Aran Security - Cross-Platform RASP Plugins

Enterprise-grade Runtime Application Self-Protection (RASP) plugins for all major mobile frameworks.

## 🎯 Overview

This directory contains production-ready RASP security plugins for:

1. **Cordova** - Apache Cordova plugin with native Android/iOS bridges
2. **Capacitor** - Ionic Capacitor plugin with modern native APIs
3. **React Native** - Native module with TurboModules support
4. **Flutter** - Platform channel plugin with method channels
5. **Ionic** - Standalone Ionic plugin (Capacitor-based)

## 🛡️ Core Security Features

All plugins implement the same comprehensive security suite:

### Native Threat Detection (C++/Kotlin/Swift)
- ✅ Root/Jailbreak Detection (23 file artifacts + Magisk detection)
- ✅ Frida Detection (/proc/self/maps scanning + port 27042)
- ✅ Debugger Detection (ptrace + TracerPid)
- ✅ Emulator Detection (Build properties + system artifacts)
- ✅ Hook Detection (Xposed, Substrate, Cydia)
- ✅ APK/IPA Tampering (Signature verification)
- ✅ Untrusted Installer Detection
- ✅ Developer Mode Detection
- ✅ ADB Enabled Detection

### Kotlin/Swift-Level Detections
- ✅ VPN Detection
- ✅ Screen Recording Detection
- ✅ Keylogger Risk (Accessibility services)
- ✅ Untrusted Keyboard Detection
- ✅ Device Lock Status
- ✅ Overlay Attack Detection
- ✅ Malware Detection (Dynamic blacklist)
- ✅ Unsecured WiFi Detection
- ✅ SMS Forwarder Apps
- ✅ Remote Access Apps

### Security Utilities
- ✅ SSL Certificate Pinning
- ✅ Screenshot Prevention (FLAG_SECURE)
- ✅ Clipboard Protection
- ✅ App Encryption (AppiCrypt integration)
- ✅ Cloud-Managed Configuration
- ✅ Real-time Telemetry

## 📁 Directory Structure

```
cross-platform-plugins/
├── cordova-plugin-aran-rasp/          # Cordova plugin
│   ├── plugin.xml
│   ├── src/android/                   # Kotlin native code
│   ├── src/ios/                       # Swift native code
│   ├── www/                           # JavaScript bridge
│   └── demo-app/                      # Cordova demo app
│
├── capacitor-plugin-aran-rasp/        # Capacitor plugin
│   ├── android/                       # Android native module
│   ├── ios/                           # iOS native module
│   ├── src/                           # TypeScript definitions
│   └── demo-app/                      # Ionic/Angular demo
│
├── react-native-aran-rasp/            # React Native module
│   ├── android/                       # Kotlin native module
│   ├── ios/                           # Swift native module
│   ├── src/                           # TypeScript/JavaScript
│   └── example/                       # RN demo app
│
├── flutter-aran-rasp/                 # Flutter plugin
│   ├── android/                       # Kotlin platform code
│   ├── ios/                           # Swift platform code
│   ├── lib/                           # Dart code
│   └── example/                       # Flutter demo app
│
└── ionic-plugin-aran-rasp/            # Ionic standalone
    ├── (Capacitor-based)
    └── demo-app/
```

## 🚀 Quick Start

### Cordova
```bash
cd cordova-plugin-aran-rasp
cordova plugin add .
```

### Capacitor
```bash
cd capacitor-plugin-aran-rasp
npm install
npx cap sync
```

### React Native
```bash
cd react-native-aran-rasp
npm install
cd ios && pod install
```

### Flutter
```bash
cd flutter-aran-rasp
flutter pub get
```

## 🔗 Integration with Aran Backend

All plugins connect to the Aran Security Cloud backend:
- **Base URL**: `http://localhost:33100` (configurable)
- **Config Sync**: `/api/v1/config/sync`
- **Telemetry**: `/api/v1/telemetry/ingest`
- **Admin API**: `/api/v1/admin/tenants`

## 📊 Comparison Matrix

| Feature | Cordova | Capacitor | React Native | Flutter | Ionic |
|---------|---------|-----------|--------------|---------|-------|
| Root Detection | ✅ | ✅ | ✅ | ✅ | ✅ |
| Frida Detection | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSL Pinning | ✅ | ✅ | ✅ | ✅ | ✅ |
| Screenshot Block | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cloud Sync | ✅ | ✅ | ✅ | ✅ | ✅ |
| TypeScript | ❌ | ✅ | ✅ | N/A | ✅ |
| Hot Reload | ❌ | ✅ | ✅ | ✅ | ✅ |
| Bundle Size | ~2MB | ~1.8MB | ~1.5MB | ~1.2MB | ~1.8MB |

## 📝 License

Proprietary - Aran Security Platform
