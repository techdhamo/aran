# ARAN RASP Capacitor Demo

This is a demo application showcasing the ARAN RASP (Runtime Application Self-Protection) Capacitor plugin.

## Features

- **Obfuscated Selectors**: Uses integer selectors (0x1A2B, 0x2B3C, etc.) instead of readable strings
- **Capacitor Plugin Integration**: Modern web-to-native bridge
- **Real-time Security Checks**: Monitor integrity, debugger, root, jailbreak, Frida, and emulator detection
- **Silent Failures**: Returns safe defaults on errors to avoid app crashes

## Security Checks

The demo demonstrates the following security checks:

- **Integrity Check** (0x1A2B): Verifies app integrity
- **Debugger Check** (0x2B3C): Detects attached debuggers
- **Root Check** (0x3C4D): Detects rooted Android devices
- **Jailbreak Check** (0x4D5E): Detects jailbroken iOS devices
- **Frida Check** (0x5E6F): Detects Frida instrumentation
- **Emulator Check** (0x6F70): Detects emulators

## Setup

### Prerequisites

- Node.js 16+
- Capacitor CLI
- Android SDK (API 21+)
- iOS SDK (iOS 12.0+)
- CocoaPods

### Installation

1. Clone the repository
2. Navigate to the capacitor_demo directory
3. Install dependencies:
   ```bash
   npm install
   npx cap add android
   npx cap add ios
   ```

### Android Setup

1. Set up your Maven credentials as environment variables:
   ```bash
   export ARAN_MAVEN_USERNAME=your_username
   export ARAN_MAVEN_PASSWORD=your_password
   ```

2. Build and run:
   ```bash
   npm run build
   npx cap sync android
   npm run android
   ```

### iOS Setup

1. Install CocoaPods dependencies:
   ```bash
   cd ios
   pod install
   cd ..
   ```

2. Build and run:
   ```bash
   npm run build
   npx cap sync ios
   npm run ios
   ```

## Usage

The demo app provides a simple UI to:

- Initialize the RASP engine
- Run individual security checks
- Run all security checks at once
- View results with color-coded indicators

### Result Codes

- **0x7F3D**: Security OK (green)
- **0x1A2B**: Suspicious (orange)
- **Other**: Threat detected (red)

## Architecture

```
Capacitor App (Web)
    ↓ Capacitor Plugin
AranRASP Plugin
    ↓
Native Core (AAR/Pod)
    ↓
Pre-compiled Security Logic
```

## Security Notes

- All selectors are obfuscated integers
- No sensitive strings in framework code
- "Dumb" passthrough to native cores
- Silent failures to prevent app crashes
