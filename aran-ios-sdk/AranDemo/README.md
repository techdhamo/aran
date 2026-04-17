# Aran Security iOS Demo App

Demo application showcasing the Aran iOS SDK integration with comprehensive security monitoring and hardware attestation.

## Features

### Security Monitoring Dashboard
- **Real-time Threat Detection**: Displays current security status with threat count
- **Detailed Security Checks**: Shows status of all 10 security detections:
  - Jailbreak detection
  - Frida detection
  - Debugger detection
  - Emulator detection
  - Hooking framework detection
  - Code tampering detection
  - VPN detection
  - Screen recording detection
  - Remote access app detection
  - SMS forwarder app detection

### Interactive Features
1. **Refresh Security Scan**: Manual trigger for comprehensive security check
2. **Generate Sigil**: Create hardware-attested JWT token using Secure Enclave
3. **Test API Call**: Demonstrates automatic X-Aran-Sigil header injection

### Threat Handling
- **Custom Threat Listener**: Implements `AranThreatListener` protocol
- **Real-time Alerts**: UIAlertController notifications when threats are detected
- **NotificationCenter Integration**: Broadcasts for hybrid framework bridges

## Architecture

```
AranDemo/
├── AppDelegate.swift          # SDK initialization & threat listener
├── ViewController.swift       # Main UI with security dashboard
├── Info.plist                 # App configuration with URL schemes
└── AranDemo.xcodeproj/        # Xcode project configuration
```

## Setup

### 1. Build Aran Framework

```bash
cd ../Aran
xcodebuild -scheme Aran -configuration Release
```

### 2. Open in Xcode

```bash
open AranDemo.xcodeproj
```

### 3. Configure Signing

1. Select **AranDemo** target
2. Go to **Signing & Capabilities**
3. Select your **Team**
4. Xcode will automatically provision the app

### 4. Run on Device

**Important:** Security features require a physical device. Simulator will show emulator detection.

```bash
# Connect iPhone/iPad
# Select device in Xcode
# Press Cmd+R to build and run
```

## Usage

### Initial Launch

On app launch, the SDK automatically:
1. Initializes with DEV environment
2. Performs initial security scan
3. Logs results to console
4. Displays threat count on UI

### Security Dashboard

The main screen shows:
- **Threat Count**: Large number indicating active threats (0 = secure)
- **Status Message**: "✅ Device is Secure" or "⚠️ Security Threats Detected"
- **Detail Rows**: Individual check results with ✅/❌ indicators
- **Device Fingerprint**: Unique device identifier (truncated)

### Generate Sigil

Tap **"Generate Sigil (JWT)"** to:
1. Create hardware-attested JWT using Secure Enclave
2. Include current threat status in payload
3. Display JWT in alert (first 100 chars)
4. Copy to clipboard option

Example Sigil structure:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkRFTU9fTElDRU5TRV9LRVkifQ.eyJpc3MiOiJhcmFuLXNlY3VyaXR5IiwiZGV2aWNlRmluZ2VycHJpbnQiOiIuLi4iLCJ0aHJlYXRTdGF0dXMiOnsiaXNKYWlsYnJva2VuIjpmYWxzZSwiaGFzVGhyZWF0IjpmYWxzZX19.signature
```

### Test API Call

Tap **"Test API Call (Auto Sigil)"** to:
1. Make GET request to `https://httpbin.org/headers`
2. AranURLProtocol automatically intercepts request
3. Generates Sigil for request body
4. Injects `X-Aran-Sigil` header
5. Displays success alert with Sigil preview

This demonstrates the **OmniNet** network interceptor in action.

## Console Output

### Initialization
```
✅ Aran Security SDK initialized
📊 Initial Security Status:
   - Jailbroken: false
   - Frida: false
   - Debugger: false
   - Emulator: true (if simulator)
   - Hooked: false
   - VPN: false
   - Screen Recording: false
   - Threats: 0
```

### Threat Detection
```
⚠️ Threat Detected!
   - Threat Count: 2
Aran: Threat Details:
  - Device is jailbroken
  - VPN active
```

### Sigil Generation
```
🔐 Sigil Generated: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkRFTU9fTElDRU5TRV9LRVkifQ...
```

### API Call
```
🌐 Making API call to httpbin.org...
✅ API call successful with auto-injected Sigil
```

## Testing Scenarios

### 1. Clean Device (Simulator)
- Expected: 1 threat (emulator detected)
- All other checks should be ✅ NO

### 2. Jailbroken Device
- Expected: Multiple threats detected
- Jailbreak check: ❌ YES
- Possibly hooking frameworks detected

### 3. VPN Active
- Connect to VPN
- Tap "Refresh Security Scan"
- VPN Active: ❌ YES

### 4. Screen Recording
- Start screen recording
- App detects `UIScreen.main.isCaptured`
- Screen Recording: ❌ YES

### 5. Debugger Attached
- Run with Xcode debugger
- Debugger Attached: ❌ YES (sysctl detects P_TRACED)

## Threat Listener Implementation

```swift
func onThreatDetected(status: DeviceStatus, reactionPolicy: ReactionPolicy) {
    DispatchQueue.main.async {
        print("⚠️ Threat Detected!")
        print("   - Threat Count: \(status.threatCount)")
        
        // Show alert to user
        let alert = UIAlertController(
            title: "Security Alert",
            message: "\(status.threatCount) security threat(s) detected.",
            preferredStyle: .alert
        )
        // Present alert...
    }
}
```

## NotificationCenter Integration

For hybrid frameworks (Flutter, React Native):

```swift
NotificationCenter.default.addObserver(
    self,
    selector: #selector(handleThreatNotification(_:)),
    name: AranSecure.threatDetectedNotification,
    object: nil
)

@objc private func handleThreatNotification(_ notification: Notification) {
    if let userInfo = notification.userInfo,
       let status = userInfo["status"] as? [String: Any] {
        // Handle threat data
    }
}
```

## Requirements

- iOS 13.0+
- Xcode 13.0+
- Swift 5.5+
- Physical device recommended (simulator shows emulator detection)

## Troubleshooting

### Framework Not Found
```
Ensure Aran.framework is in parent directory:
aran-ios-sdk/
├── Aran/
│   └── (framework files)
└── AranDemo/
    └── (demo app)
```

### Signing Issues
1. Select AranDemo target
2. Signing & Capabilities tab
3. Choose your development team
4. Xcode auto-provisions

### Secure Enclave Errors
- Secure Enclave requires physical device
- Simulator falls back to standard P256 key
- No functionality difference for demo

## License

Apache License 2.0

## Support

- **Email**: support@aran.mazhai.org
- **Docs**: https://docs.aran.mazhai.org
- **Dashboard**: https://dashboard.aran.mazhai.org
