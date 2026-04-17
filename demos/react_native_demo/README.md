# ARAN RASP React Native Demo

This is a demo application showcasing the ARAN RASP (Runtime Application Self-Protection) React Native TurboModule plugin.

## Features

- **TurboModule/JSI Integration**: Direct native access bypassing the React Native Bridge
- **Obfuscated Selectors**: Uses integer selectors (0x1A2B, 0x2B3C, etc.) instead of readable strings
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
- React Native CLI
- Android SDK (API 21+)
- iOS SDK (iOS 12.0+)
- CocoaPods

### Installation

1. Clone the repository
2. Navigate to the react_native_demo directory
3. Install dependencies:
   ```bash
   npm install
   ```

### Android Setup

1. Set up your Maven credentials as environment variables:
   ```bash
   export ARAN_MAVEN_USERNAME=your_username
   export ARAN_MAVEN_PASSWORD=your_password
   ```

2. Build and run:
   ```bash
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
React Native App (TypeScript)
    ↓ TurboModule/JSI (Direct Native Access)
AranTurboModule
    ↓
Native Core (libARANRasp.so/.a)
    ↓
Pre-compiled Security Logic
```

## Security Notes

- All selectors are obfuscated integers
- No sensitive strings in framework code
- TurboModule/JSI bypasses Bridge monitoring
- "Dumb" passthrough to native cores
- Silent failures to prevent app crashes
