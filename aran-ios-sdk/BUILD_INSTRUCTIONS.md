# Aran iOS SDK — App Store-Compliant Build Instructions

## Symbol Stripping and Obfuscation

To maximize the security of the Aran integrity module and avoid rejection by App Review, configure your Xcode project with the following settings:

### 1. Optimization Level

In **Build Settings** for your target:

- **Optimization Level (Release)**: `Optimize for Size [-Os]` or `Optimize for Speed [-O3]`
  - This inlines functions and removes dead code, making reverse engineering harder
  - Avoid `None [-O0]` in release builds

### 2. Strip Debug Symbols

In **Build Settings**:

- **Strip Debug Symbols During Copy**: `YES` (Release)
- **Strip Style**: `All Symbols` (Release)
- **Deployment Postprocessing**: `YES` (Release)

This removes all symbol names from the final binary, making it difficult to identify the integrity check functions.

### 3. Dead Code Stripping

In **Build Settings**:

- **Dead Code Stripping**: `YES` (Release)

This removes unused code paths, further obscuring the security logic.

### 4. Custom Compiler Flags

Add the following custom flags to pass a randomized XOR key at compile time:

In **Build Settings** → **Other C Flags** (Release):

```
-DARAN_XOR_KEY=0x[HEX_KEY]
```

Generate a new random hex key for each build to ensure the obfuscated strings change every time.

Example:
```
-DARAN_XOR_KEY=0x9F
```

### 5. Swift Compiler Flags

In **Build Settings** → **Other Swift Flags** (Release):

```
-Osize
```

This optimizes Swift code for size and enables additional inlining.

### 6. Disable Bitcode (Optional)

For maximum control over symbol stripping, you may choose to disable bitcode:

In **Build Settings**:

- **Enable Bitcode**: `NO`

Note: App Review requires bitcode for some app categories. Check Apple's current guidelines.

## Info.plist Configuration

Add the following to your `Info.plist` to enable URL scheme checks for cydia:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
</array>
```

## Integration with Existing Aran SDK

The `AranIntegrity.swift` module is designed to work alongside the existing `AranRASPEngine` and `AranEnvironmentalScanner`. To integrate:

1. Add `AranIntegrity.swift` and `AranIntegrity.c` to your Xcode target
2. Add `AranObfuscate.h` to your project
3. In your app initialization:

```swift
import Aran

// Perform integrity check on app launch
let integrity = AranIntegrityChecker.shared.checkIntegrity()

switch integrity {
case .secure:
    print("Device is secure")
    // Enable all features
case .jailbroken:
    print("Jailbreak detected")
    // Disable high-risk features, show degraded UI
case .debuggerAttached:
    print("Debugger attached")
    // Disable sensitive operations
case .hooked:
    print("Hooking framework detected")
    // Disable high-risk features
case .compromised:
    print("Device compromised")
    // Terminate session, show service unavailable
}
```

## App Store Compliance Checklist

- ✅ No private APIs used (only sysctl, stat, _dyld_get_image_name, canOpenURL)
- ✅ No ptrace calls (uses P_TRACED flag via sysctl)
- ✅ No exit() or abort() calls (returns enum state for graceful degradation)
- ✅ URL scheme declared in Info.plist (LSApplicationQueriesSchemes)
- ✅ Strings obfuscated with compile-time XOR cipher
- ✅ Symbol stripping enabled for release builds
- ✅ Dead code stripping enabled
- ✅ Optimization level set to -Os or -O3

## Testing

To test the integrity module without triggering false positives:

1. Use the simulator (no jailbreak)
2. Test on a clean device (no jailbreak)
3. For jailbreak testing, use a jailbroken test device only

To reset the integrity state (for unit tests):

```swift
// Only for testing — not exposed in production API
// In AranIntegrity.c: aran_reset_integrity_state()
```

## Security Notes

- The XOR key should be randomized per build to prevent signature-based detection
- The integrity salt in `generateIntegrityHeader()` should be kept secret
- Never log the raw integrity state or header value in production
- The backend should validate the integrity header and reject requests from compromised devices
