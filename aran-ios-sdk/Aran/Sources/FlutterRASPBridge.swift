import Flutter
import Foundation

// ============================================
// UNIVERSAL iOS RASP - Flutter MethodChannel Bridge
// BLACKBOX ARCHITECTURE - Static XCFramework
// ============================================

/**
 * FlutterRASPBridge - Flutter MethodChannel handler
 * Provides a bridge between Flutter Dart code and the native RASP engine
 * 
 * Usage in Flutter:
 * ```dart
 * final channel = MethodChannel('com.aran.security/rasp');
 * final result = await channel.invokeMethod('performAudit', {'selector': 0});
 * ```
 */
public class FlutterRASPBridge: NSObject, FlutterPlugin {
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.aran.security/rasp",
            binaryMessenger: registrar.messenger()
        )
        let instance = FlutterRASPBridge()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "performAudit":
            guard let args = call.arguments as? [String: Any],
                  let selector = args["selector"] as? Int else {
                result(FlutterError(code: "INVALID_ARGUMENTS", message: "Selector required", details: nil))
                return
            }
            
            // Call the Objective-C++ bridge
            let auditResult = RASPCore.invokeAudit(selector)
            result(auditResult)
            
        case "getStatus":
            guard let args = call.arguments as? [String: Any],
                  let statusType = args["statusType"] as? Int else {
                result(FlutterError(code: "INVALID_ARGUMENTS", message: "StatusType required", details: nil))
                return
            }
            
            // Call the Objective-C++ bridge
            let statusResult = RASPCore.getStatus(statusType)
            result(statusResult)
            
        case "checkSecurity":
            // Convenience method for full security check
            let auditResult = RASPCore.performAudit(selector: .fullAudit)
            result(auditResult.rawValue)
            
        case "isJailbroken":
            result(RASPCore.isJailbroken())
            
        case "isDebuggerAttached":
            result(RASPCore.isDebuggerAttached())
            
        case "isFridaAttached":
            result(RASPCore.isFridaAttached())
            
        case "getDetailedStatus":
            result(RASPCore.getDetailedStatus())
            
        default:
            result(FlutterMethodNotImplemented)
        }
    }
}

// ============================================
// ALTERNATIVE: Dart FFI Bridge (More Direct)
// ============================================

/**
 * Alternative implementation using Dart FFI
 * This is more direct and bypasses Flutter's MethodChannel overhead
 * 
 * Usage in Flutter:
 * ```dart
 * import 'dart:ffi' as ffi;
 * 
 * final dylib = ffi.DynamicLibrary.open('libaran_rasp.dylib');
 * final performAuditFunc = dylib.lookupFunction<
 *   ffi.Int32 Function(ffi.Int32),
 *   int Function(int)
 * >('universal_rasp_execute_audit');
 * 
 * final result = performAuditFunc(0);
 * ```
 * 
 * Note: For static library integration, use the Flutter iOS native plugin
 * mechanism instead of FFI to avoid dynamic library loading issues.
 */
