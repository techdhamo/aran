# ARAN RASP Xamarin/MAUI Demo

This is a demo application showcasing the ARAN RASP (Runtime Application Self-Protection) Xamarin/MAUI plugin.

## Features

- **Native References Integration**: Direct native library access
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

- .NET 6.0 or higher
- Visual Studio 2022 or Visual Studio for Mac
- Android SDK (API 21+)
- iOS SDK (iOS 12.0+)

### Installation

1. Clone the repository
2. Open the Xamarin/MAUI project in Visual Studio
3. Copy the RASP bridge script from `../../plugins/xamarin_maui/rasp_bridge.cs` to your project
4. Copy the native libraries (libARANRasp.so for Android, libARANRasp.a for iOS) to:
   - Android: `Platforms/Android/libs/`
   - iOS: `Platforms/iOS/`

### Android Setup

1. Set up your Maven credentials as environment variables:
   ```bash
   export ARAN_MAVEN_USERNAME=your_username
   export ARAN_MAVEN_PASSWORD=your_password
   ```

2. Build and run:
   - In Visual Studio: Set Android as target device → Run

### iOS Setup

1. Build and run:
   - In Visual Studio: Set iOS as target device → Run
   - Or use Xcode to build and run on device or simulator

## Usage

The demo page provides a simple UI to:

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
Xamarin/MAUI App (C#)
    ↓ Native References
Native Core (libARANRasp.so/.a)
    ↓
Pre-compiled Security Logic
```

## Security Notes

- All selectors are obfuscated integers
- No sensitive strings in framework code
- "Dumb" passthrough to native cores
- Silent failures to prevent app crashes
