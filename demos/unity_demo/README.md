# ARAN RASP Unity Demo

This is a demo application showcasing the ARAN RASP (Runtime Application Self-Protection) Unity plugin.

## Features

- **P/Invoke Integration**: Direct native library access
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

- Unity 2021.3 or higher
- Android SDK (API 21+)
- iOS SDK (iOS 12.0+)

### Installation

1. Clone the repository
2. Open the Unity project in Unity Editor
3. Copy the RASP bridge script from `../../plugins/unity/rasp_bridge.cs` to your Assets folder
4. Copy the native libraries (libARANRasp.so for Android, libARANRasp.a for iOS) to:
   - Android: `Assets/Plugins/Android/libs/`
   - iOS: `Assets/Plugins/iOS/`

### Android Setup

1. Set up your Maven credentials as environment variables:
   ```bash
   export ARAN_MAVEN_USERNAME=your_username
   export ARAN_MAVEN_PASSWORD=your_password
   ```

2. Build and run:
   - In Unity Editor: File → Build Settings → Android → Build and Run

### iOS Setup

1. Build and run:
   - In Unity Editor: File → Build Settings → iOS → Build
   - Open the generated Xcode project
   - Build and run on device or simulator

## Usage

The demo scene provides a simple UI to:

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
Unity App (C#)
    ↓ P/Invoke
Native Core (libARANRasp.so/.a)
    ↓
Pre-compiled Security Logic
```

## Security Notes

- All selectors are obfuscated integers
- No sensitive strings in framework code
- "Dumb" passthrough to native cores
- Silent failures to prevent app crashes
