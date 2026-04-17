# Cross-Platform RASP Plugins - Implementation Roadmap

## 📋 Project Scope

Based on IDFC RASP5 analysis, implementing 5 complete framework plugins:

### Source Analysis (IDFC RASP5)
- **Cordova Plugin**: Commercial RASP SDK v6.2.3-Beta
- **Core Features**: 18 Android threats, 13 iOS threats
- **Native Code**: Kotlin (Android), Swift (iOS)
- **JavaScript Bridge**: Cordova exec() pattern
- **Additional Modules**: AppiCrypt, Certificate Pinning

### Target Implementations

#### 1. Cordova Plugin ✅
**Package**: `cordova-plugin-aran-rasp`
- Native Android (Kotlin) - reuse Aran SDK
- Native iOS (Swift) - new implementation
- JavaScript bridge (www/aran-rasp.js)
- Demo app (Cordova CLI project)

#### 2. Capacitor Plugin ✅
**Package**: `@aran-security/capacitor-rasp`
- Android native module (Kotlin)
- iOS native module (Swift)
- TypeScript definitions
- Demo app (Ionic/Angular)

#### 3. React Native Module ✅
**Package**: `react-native-aran-rasp`
- Android native module (Kotlin + TurboModules)
- iOS native module (Swift + New Architecture)
- TypeScript/JavaScript API
- Example app (React Native CLI)

#### 4. Flutter Plugin ✅
**Package**: `flutter_aran_rasp`
- Android platform channel (Kotlin)
- iOS platform channel (Swift)
- Dart API
- Example app (Flutter)

#### 5. Ionic Plugin ✅
**Package**: `@aran-security/ionic-rasp`
- Capacitor-based wrapper
- Ionic-specific utilities
- Demo app (Ionic/React)

## 🎯 Core Features Matrix

| Feature | Android | iOS | Priority |
|---------|---------|-----|----------|
| Root/Jailbreak Detection | ✅ | ✅ | P0 |
| Frida Detection | ✅ | ✅ | P0 |
| Debugger Detection | ✅ | ✅ | P0 |
| Emulator/Simulator | ✅ | ✅ | P0 |
| Hook Detection | ✅ | ✅ | P0 |
| APK/IPA Tampering | ✅ | ✅ | P0 |
| Untrusted Installer | ✅ | ✅ | P1 |
| Developer Mode | ✅ | N/A | P1 |
| ADB Enabled | ✅ | N/A | P1 |
| VPN Detection | ✅ | ✅ | P1 |
| Screen Recording | ✅ | ✅ | P1 |
| Screenshot Prevention | ✅ | ✅ | P1 |
| Overlay Attack | ✅ | N/A | P2 |
| Malware Detection | ✅ | N/A | P2 |
| SSL Pinning | ✅ | ✅ | P0 |
| Cloud Config Sync | ✅ | ✅ | P1 |
| Telemetry | ✅ | ✅ | P1 |

## 🔧 Technical Architecture

### Shared Native Code Strategy
- **Android**: Leverage existing `aran-android-sdk` (Kotlin)
- **iOS**: Create new `aran-ios-sdk` (Swift) mirroring Android features
- **Bridge Pattern**: Each framework has its own native bridge to shared SDK

### Code Reuse Plan
```
aran-android-sdk/aran-secure/  (EXISTING)
    ├── AranSecure.kt
    ├── DeviceStatus.kt
    ├── AranNative (C++)
    └── AranThreatListener.kt

aran-ios-sdk/AranSecure/  (NEW)
    ├── AranSecure.swift
    ├── DeviceStatus.swift
    ├── AranNative (C++)
    └── AranThreatDelegate.swift

Plugins (Bridge Layer):
    ├── cordova-plugin-aran-rasp/
    │   ├── src/android/AranRaspPlugin.kt → calls AranSecure
    │   └── src/ios/AranRaspPlugin.swift → calls AranSecure
    │
    ├── capacitor-plugin-aran-rasp/
    │   ├── android/AranRaspPlugin.kt → calls AranSecure
    │   └── ios/AranRaspPlugin.swift → calls AranSecure
    │
    ├── react-native-aran-rasp/
    │   ├── android/AranRaspModule.kt → calls AranSecure
    │   └── ios/AranRaspModule.swift → calls AranSecure
    │
    └── flutter-aran-rasp/
        ├── android/AranRaspPlugin.kt → calls AranSecure
        └── ios/AranRaspPlugin.swift → calls AranSecure
```

## 📦 Deliverables Per Framework

### Each Plugin Includes:
1. **Native Code** (Android + iOS)
2. **JavaScript/TypeScript/Dart API**
3. **Type Definitions**
4. **README.md** with integration guide
5. **package.json** / pubspec.yaml
6. **Demo App** (fully functional)
7. **LICENSE** file

### Demo App Features:
- Security scan button
- Threat status display
- Cloud config sync demo
- SSL pinning test
- Screenshot prevention demo
- Custom threat handler (CUSTOM policy)

## 🚀 Implementation Order

1. **Phase 1**: Cordova (baseline, closest to IDFC RASP5)
2. **Phase 2**: Capacitor (modern Ionic)
3. **Phase 3**: React Native (popular framework)
4. **Phase 4**: Flutter (growing adoption)
5. **Phase 5**: Ionic standalone (Capacitor wrapper)

## 📊 Success Criteria

- ✅ All plugins compile without errors
- ✅ Demo apps run on Android/iOS
- ✅ All P0 features functional
- ✅ Cloud backend integration working
- ✅ TypeScript definitions accurate
- ✅ Documentation complete
- ✅ CUSTOM reaction policy supported

## 🔗 Backend Integration

All plugins connect to Aran Cloud:
- **Config Sync**: `GET /api/v1/config/sync?os=android&rasp_version=1.0.0&license_key=XXX`
- **Telemetry**: `POST /api/v1/telemetry/ingest`
- **WAF**: `X-Aran-Sigil` header with hardware-signed JWT

## 📝 Next Steps

Starting with Cordova plugin implementation...
