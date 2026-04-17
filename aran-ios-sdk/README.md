# Aran iOS SDK

Enterprise-grade iOS security framework with hardware-attested threat detection and runtime application self-protection (RASP).

## Features

### Core Security Engine
- **Jailbreak Detection**: File-based, sandbox violation, and fork() checks
- **Frida Detection**: Dynamic library inspection for hooking frameworks
- **Debugger Detection**: sysctl-based P_TRACED flag monitoring
- **Emulator Detection**: Compile-time and runtime simulator checks
- **Code Tampering**: Binary signature verification

### Environmental Scanning
- **VPN Detection**: Network interface and proxy configuration analysis
- **Screen Recording**: Multi-screen capture detection
- **Remote Access Apps**: URL scheme checks for TeamViewer, AnyDesk, etc.
- **SMS Forwarder Apps**: Detection of message forwarding applications

### Hardware Attestation
- **Secure Enclave Integration**: P256 signing keys stored in iOS Secure Enclave
- **Sigil Generation**: Hardware-attested JWT tokens for API requests
- **Network Interception**: Automatic X-Aran-Sigil header injection via URLProtocol

## Architecture

```
Aran.framework/
├── AranSecure.swift              # Main entry point
├── AranRASPEngine.swift          # Low-level RASP checks
├── AranEnvironmentalScanner.swift # Continuous threat monitoring
├── AranSigilEngine.swift         # Secure Enclave attestation
├── AranURLProtocol.swift         # Network interceptor
├── DeviceStatus.swift            # Threat status model
├── AranEnvironment.swift         # DEV/UAT/RELEASE
├── ReactionPolicy.swift          # Threat response policies
└── AranThreatListener.swift      # Delegate protocol
```

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/aran-security/aran-ios-sdk.git", from: "1.0.0")
]
```

### CocoaPods

```ruby
pod 'Aran', '~> 1.0.0'
```

### Manual

1. Download `Aran.framework`
2. Drag into Xcode project
3. Add to "Embedded Binaries"

## Usage

### Basic Initialization

```swift
import Aran

AranSecure.start(
    licenseKey: "YOUR_LICENSE_KEY",
    environment: .release,
    reactionPolicy: .warnUser
)
```

### Custom Threat Handling

```swift
class SecurityManager: AranThreatListener {
    func onThreatDetected(status: DeviceStatus, reactionPolicy: ReactionPolicy) {
        print("Threats: \(status.threatCount)")
        
        if status.isJailbroken {
            // Handle jailbreak
        }
        
        if status.fridaDetected {
            // Handle Frida
        }
    }
}

AranSecure.start(
    licenseKey: "YOUR_LICENSE_KEY",
    environment: .release,
    reactionPolicy: .custom,
    listener: SecurityManager()
)
```

### Manual Security Check

```swift
let status = AranSecure.shared.checkEnvironment()

if status.hasThreat {
    print("Device compromised: \(status.threatCount) threats")
}
```

### Hardware-Attested API Calls

```swift
// Automatic injection via URLProtocol
let request = URLRequest(url: URL(string: "https://api.example.com")!)
URLSession.shared.dataTask(with: request).resume()
// X-Aran-Sigil header automatically added

// Manual Sigil generation
let sigil = try AranSecure.shared.generateSigil()
```

## Reaction Policies

| Policy | Behavior |
|--------|----------|
| `logOnly` | Log threats to console |
| `warnUser` | Show UIAlertController |
| `blockApi` | Prevent network requests |
| `killApp` | Terminate application |
| `blockAndReport` | Report to backend + block |
| `custom` | Delegate to listener |

## Device Status

```swift
public class DeviceStatus {
    let isJailbroken: Bool
    let fridaDetected: Bool
    let debuggerAttached: Bool
    let emulatorDetected: Bool
    let hooked: Bool
    let tampered: Bool
    let vpnActive: Bool
    let screenRecording: Bool
    let remoteAccessActive: Bool
    let smsForwarderActive: Bool
    let deviceFingerprint: String
    let appId: String
    let hasThreat: Bool
    let threatCount: Int
}
```

## Requirements

- iOS 13.0+
- Swift 5.5+
- Xcode 13.0+

## License

Apache License 2.0

## Support

- **Email**: support@aran.mazhai.org
- **Docs**: https://docs.aran.mazhai.org
- **Dashboard**: https://dashboard.aran.mazhai.org
