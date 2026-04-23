<div align="center">

# 🛡️ Aran

### **Code-to-Cloud RASP Ecosystem**

*Runtime application self-protection, from the first line of source to the last byte in production.*

[![Java](https://img.shields.io/badge/Java-21%20%7C%20Project%20Loom-orange)]()
[![Android](https://img.shields.io/badge/Android-SDK-3DDC84?logo=android&logoColor=white)]()
[![iOS](https://img.shields.io/badge/iOS-SDK-000?logo=apple&logoColor=white)]()
[![C++](https://img.shields.io/badge/C%2B%2B-RASP%20Core-00599C?logo=cplusplus&logoColor=white)]()
[![OWASP](https://img.shields.io/badge/OWASP-MASVS-blue)]()
[![Compliance](https://img.shields.io/badge/Compliance-RBI%20%7C%20GDPR-green)]()

**`mazhai.org`** · **`aran.mazhai.org`** · Package namespace `org.mazhai` · Ports `33100–33199`

</div>

---

## Overview

**Aran** is the security runtime behind [Mazhai Technologies'](https://mazhai.org) *Code-to-Cloud* platform. It delivers **Runtime Application Self-Protection (RASP)** across every major mobile and desktop runtime through a single universal C++ core with native bridges, backed by a Java 21 / Project Loom ingestion pipeline and a WAAP-class detection dashboard.

Designed to compete with **Appdome · Imperva · Datadog Mobile RASP**, Aran is built on open standards and mapped to **OWASP MASVS** and **RBI** regulatory controls.

## Architecture at a glance

```
┌─────────────────────────────────────────────────────────────────┐
│  Apps (Android · iOS · Cordova · Capacitor · Flutter · RN ·     │
│        Unity · Xamarin/MAUI · NativeScript · Web)               │
│                         ▲                                       │
│               Language bridges (this repo)                      │
│                         │                                       │
│         Universal RASP Core (C++ — universal_rasp_core.cpp)     │
│                         │                                       │
│       JNI / ObjC++ / Turbo / JS FFI transport (port 33100+)     │
│                         ▼                                       │
│   Aran Backend (Java 21 · Virtual Threads · Kafka ingestion)    │
│                         ▼                                       │
│   Aran Dashboard · WAAP · Red-Team · Maven Distribution         │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Module | Purpose |
|---|---|
| `aran-android-sdk/` | Native Android SDK · CMake-built `aran-secure` binary · JNI bridge |
| `aran-ios-sdk/` | iOS SDK · Objective-C++ bridge (`ios_objcpp_bridge.mm`) |
| `aran-backend/` | Java 21 ingestion & detection services (Project Loom, Kafka) |
| `aran-dashboard/` | Operator console for fleet telemetry & incidents |
| `aran-waap/` | Web Application & API Protection adapter |
| `aran-red-team/` | Adversarial test suites, jailbreak/root simulators |
| `aran-website/` | Marketing & docs site |
| `mazhai-central/` | Control-plane services for the Mazhai ecosystem |
| `maven_infrastructure/` | Private Maven repo bootstrap (see `maven_repository_guide.md`) |
| `plugins/` · `demos/` | Example integrations and reference apps |

### Runtime bridges (this repo root)

| File | Target runtime |
|---|---|
| `universal_rasp_core.cpp` | Language-agnostic RASP core |
| `android_jni_bridge.cpp` | Android / Java / Kotlin |
| `ios_objcpp_bridge.mm` | iOS / Swift / Objective-C |
| `cordova_capacitor_rasp.java` | Apache Cordova & Ionic Capacitor |
| `flutter_rasp_plugin.dart` | Flutter / Dart |
| `react_native_rasp_turbo.cpp` | React Native (TurboModule) |
| `nativescript_rasp.h` | NativeScript |
| `unity_rasp_bridge.cs` | Unity (C#) |
| `xamarin_maui_rasp.cs` | Xamarin / .NET MAUI |
| `legacy_framework_bridges.js` | Legacy JS frameworks |

## Key capabilities

- **Anti-tampering**: integrity checks, code-signing verification, Frida/Xposed/Cycript detection.
- **Environment hardening**: root/jailbreak detection, emulator fingerprinting, debugger traps.
- **Network defence**: SSL pinning, TLS downgrade detection, proxy/MITM hooks (Burp-aware).
- **Memory & code protection**: anti-hooking, runtime string obfuscation, JNI call-gate verification.
- **Compliance**: OWASP MASVS L1/L2 controls, RBI Cyber Security Framework mapping, GDPR audit trail.
- **Telemetry**: zero-PII event stream over `:33100-33199` to the Aran backend.

Full coverage is documented in [`SECURITY.md`](./SECURITY.md) and [`docs/`](./docs/).

## Documentation

Deep-dives live under [`docs/`](./docs/README.md):

- `VISION_AND_STRATEGY.md` — Dual-brand (Mazhai × Aran) strategy and 8-track product roadmap.
- `TECHNICAL_ARCHITECTURE.md` — Code-to-Cloud data flow, Java 21 / Loom ingestion, C++ JNI RASP layer, port 33100 standard.
- `AGILE_BACKLOG_PHASE_1.md` — *Iron Core* stories and Android + Backend acceptance criteria.
- `GTM_AND_COMPLIANCE.md` — Competitive matrix vs. Appdome / Imperva / Datadog + regulatory mapping.
- `ARAN_IMPLEMENTATION_GUIDE.md` — Hands-on integration guide.
- `DESIGN_REVIEW_GAP_ANALYSIS.md` — Design-time security review methodology.

## Build & run (selected)

Android SDK:
```bash
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease
```

Backend (Kafka + services):
```bash
docker compose -f docker-compose.kafka.yml up -d
docker compose up -d
```

CI lives in [`Jenkinsfile`](./Jenkinsfile) and `.github/workflows/` (build-android-sdk, build-ios-sdk).

## Ecosystem standards

- **Domains**: `mazhai.org`, `aran.mazhai.org`
- **Package namespace**: `org.mazhai`
- **Port range**: `33100–33199`
- **Compliance**: OWASP MASVS (L1/L2), RBI Cyber Security Framework, GDPR

## License & contact

Proprietary — © Mazhai Technologies. All rights reserved.

Lead: **Dhamodaran Narayana Perumal** · [dhamodaran@outlook.in](mailto:dhamodaran@outlook.in) · [dhamo.in](https://dhamo.in)
