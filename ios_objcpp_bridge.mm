/**
 * UNIVERSAL BLACKBOX RASP ENGINE - iOS Objective-C++ Bridge
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: iOS (Objective-C++)
 * Architecture: Objective-C++ with hidden visibility attributes
 */

#import <Foundation/Foundation.h>
#include "universal_rasp_core.cpp"

// ============================================
// OBFUSCATED SELECTORS
// ============================================

namespace RASPSelectors {
    static constexpr int fullAudit = 0x1A2B;
    static constexpr int rootJailbreakOnly = 0x1A2C;
    static constexpr int debuggerOnly = 0x1A2D;
    static constexpr int fridaOnly = 0x1A2E;
}

namespace RASPStatusTypes {
    static constexpr int rootJailbreak = 0x2A2B;
    static constexpr int debugger = 0x2A2C;
    static constexpr int frida = 0x2A2D;
}

namespace RASPErrorCodes {
    static constexpr int securityOK = 0x7F3D;
    static constexpr int suspicious = 0x7F3C;
    static constexpr int highlySuspicious = 0x7F3B;
    static constexpr int confirmedTamper = 0x7F3A;
}

// ============================================
// OBJECTIVE-C++ BRIDGE CLASS
// ============================================

/**
 * RASPCore - Universal RASP Provider
 * Single entry point for all frameworks
 * Uses hidden visibility to keep out of Mach-O symbol table
 */
__attribute__((visibility("hidden")))
@interface RASPCore : NSObject
+ (NSInteger)invokeAudit:(NSInteger)selector;
+ (NSInteger)getStatus:(NSInteger)statusType;
+ (NSDictionary*)getDetailedStatus;
+ (void)initialize;
+ (void)shutdown;
@end

@implementation RASPCore

/**
 * Universal audit invocation
 * 
 * @param selector Obfuscated selector value
 * @return Randomized error code from native engine
 */
+ (NSInteger)invokeAudit:(NSInteger)selector {
    @try {
        return universal_rasp_execute_audit((int)selector);
    } @catch (NSException *exception) {
        // Silent failure - return randomized error code
        return RASPErrorCodes::securityOK;
    }
}

/**
 * Get detection status
 * 
 * @param statusType Obfuscated status type value
 * @return Detection status (0 = not detected, 1 = detected)
 */
+ (NSInteger)getStatus:(NSInteger)statusType {
    @try {
        return universal_rasp_get_status((int)statusType);
    } @catch (NSException *exception) {
        // Silent failure - return 0 (not detected)
        return 0;
    }
}

/**
 * Get detailed status
 * 
 * @return Dictionary with all detection statuses
 */
+ (NSDictionary*)getDetailedStatus {
    @try {
        // Get detection statuses
        int rootJailbreak = universal_rasp_get_status(RASPStatusTypes::rootJailbreak);
        int debugger = universal_rasp_get_status(RASPStatusTypes::debugger);
        int frida = universal_rasp_get_status(RASPStatusTypes::frida);
        int securityResult = universal_rasp_execute_audit(RASPSelectors::fullAudit);
        
        return @{
            @"rootJailbreakDetected": @(rootJailbreak == 1),
            @"debuggerDetected": @(debugger == 1),
            @"fridaDetected": @(frida == 1),
            @"securityResult": @(securityResult)
        };
    } @catch (NSException *exception) {
        // Silent failure - return empty dictionary
        return @{};
    }
}

/**
 * Initialize RASP engine
 */
+ (void)initialize {
    @try {
        universal_rasp_initialize();
    } @catch (NSException *exception) {
        // Silent failure
    }
}

/**
 * Shutdown RASP engine
 */
+ (void)shutdown {
    @try {
        universal_rasp_shutdown();
    } @catch (NSException *exception) {
        // Silent failure
    }
}

@end

// ============================================
// EXTERN C INTERFACE FOR FRAMEWORK BRIDGES
// ============================================

extern "C" {

/**
 * C-style interface for framework bridges
 * Easier to bridge from Swift, Unity, etc.
 */
__attribute__((visibility("hidden")))
int rasp_invoke_audit_c(int selector) {
    return [RASPCore invokeAudit:selector];
}

__attribute__((visibility("hidden")))
int rasp_get_status_c(int statusType) {
    return [RASPCore getStatus:statusType];
}

__attribute__((visibility("hidden")))
void rasp_initialize_c() {
    [RASPCore initialize];
}

__attribute__((visibility("hidden")))
void rasp_shutdown_c() {
    [RASPCore shutdown];
}

}

// ============================================
// SWIFT EXTENSION (for reference)
// ============================================

/**
 * Swift extension for native iOS applications
 * 
 * ```swift
 * import Foundation
 * 
 * // Extension for easy Swift usage
 * extension RASPCore {
 *     
 *     enum AuditSelector: Int {
 *         case fullAudit = 0x1A2B
 *         case rootJailbreakOnly = 0x1A2C
 *         case debuggerOnly = 0x1A2D
 *         case fridaOnly = 0x1A2E
 *     }
 *     
 *     enum StatusType: Int {
 *         case rootJailbreak = 0x2A2B
 *         case debugger = 0x2A2C
 *         case frida = 0x2A2D
 *     }
 *     
 *     enum SecurityResult: Int {
 *         case securityOK = 0x7F3D
 *         case suspicious = 0x7F3C
 *         case highlySuspicious = 0x7F3B
 *         case confirmedTamper = 0x7F3A
 *     }
 *     
 *     static func performAudit(selector: AuditSelector = .fullAudit) -> SecurityResult {
 *         let result = invokeAudit(selector.rawValue)
 *         return SecurityResult(rawValue: result) ?? .securityOK
 *     }
 *     
 *     static func getDetectionStatus(statusType: StatusType) -> Bool {
 *         return getStatus(statusType.rawValue) == 1
 *     }
 *     
 *     static func checkSecurity() -> SecurityResult {
 *         return performAudit(selector: .fullAudit)
 *     }
 *     
 *     static func isJailbroken() -> Bool {
 *         return getDetectionStatus(statusType: .rootJailbreak)
 *     }
 *     
 *     static func isDebuggerAttached() -> Bool {
 *         return getDetectionStatus(statusType: .debugger)
 *     }
 *     
 *     static func isFridaAttached() -> Bool {
 *         return getDetectionStatus(statusType: .frida)
 *     }
 *     
 *     static func getDetailedStatus() -> [String: Any] {
 *         return getDetailedStatus() as [String: Any]
 *     }
 * }
 * ```
 */

// ============================================
// USAGE IN SWIFT
// ============================================

/**
 * Swift usage:
 * 
 * ```swift
 * import Foundation
 * 
 * // Direct usage
 * let result = RASPCore.invokeAudit(0x1A2B)
 * let isJailbroken = RASPCore.getStatus(0x2A2B) == 1
 * 
 * // Using extension (if added)
 * let result = RASPCore.performAudit(selector: .fullAudit)
 * let isJailbroken = RASPCore.isJailbroken()
 * 
 * // Detailed status
 * let status = RASPCore.getDetailedStatus()
 * print("Status: \(status)")
 * ```
 */

// ============================================
// USAGE IN UNITY (C# P/Invoke)
// ============================================

/**
 * Unity C# P/Invoke wrapper (for reference)
 * 
 * ```csharp
 * using System.Runtime.InteropServices;
 * using UnityEngine;
 * 
 * public class RASPNative {
 *     #if UNITY_IOS
 *     [DllImport("__Internal")]
 *     private static extern int rasp_invoke_audit_c(int selector);
 *     
 *     [DllImport("__Internal")]
 *     private static extern int rasp_get_status_c(int statusType);
 *     
 *     [DllImport("__Internal")]
 *     private static extern void rasp_initialize_c();
 *     
 *     [DllImport("__Internal")]
 *     private static extern void rasp_shutdown_c();
 *     #elif UNITY_ANDROID
 *     [DllImport("aran_rasp")]
 *     private static extern int Java_com_aran_rasp_RASPNativeModule_a1_impl(int selector);
 *     
 *     [DllImport("aran_rasp")]
 *     private static extern int Java_com_aran_rasp_RASPNativeModule_b2_impl(int statusType);
 *     
 *     [DllImport("aran_rasp")]
 *     private static extern void Java_com_aran_rasp_RASPNativeModule_d4_impl();
 *     
 *     [DllImport("aran_rasp")]
 *     private static extern void Java_com_aran_rasp_RASPNativeModule_e5_impl();
 *     #endif
 *     
 *     public static int ExecuteAudit(int selector) {
 *         #if UNITY_IOS
 *         return rasp_invoke_audit_c(selector);
 *         #elif UNITY_ANDROID
 *         return Java_com_aran_rasp_RASPNativeModule_a1_impl(selector);
 *         #else
 *         return 0x7F3D; // SECURITY_OK
 *         #endif
 *     }
 *     
 *     public static int GetStatus(int statusType) {
 *         #if UNITY_IOS
 *         return rasp_get_status_c(statusType);
 *         #elif UNITY_ANDROID
 *         return Java_com_aran_rasp_RASPNativeModule_b2_impl(statusType);
 *         #else
 *         return 0;
 *         #endif
 *     }
 *     
 *     public static void Initialize() {
 *         #if UNITY_IOS
 *         rasp_initialize_c();
 *         #elif UNITY_ANDROID
 *         Java_com_aran_rasp_RASPNativeModule_d4_impl();
 *         #endif
 *     }
 *     
 *     public static void Shutdown() {
 *         #if UNITY_IOS
 *         rasp_shutdown_c();
 *         #elif UNITY_ANDROID
 *         Java_com_aran_rasp_RASPNativeModule_e5_impl();
 *         #endif
 *     }
 *     
 *     public static int CheckSecurity() {
 *         return ExecuteAudit(0x1A2B);
 *     }
 *     
 *     public static bool IsRootJailbroken() {
 *         return GetStatus(0x2A2B) == 1;
 *     }
 *     
 *     public static bool IsDebuggerAttached() {
 *         return GetStatus(0x2A2C) == 1;
 *     }
 *     
 *     public static bool IsFridaAttached() {
 *         return GetStatus(0x2A2D) == 1;
 *     }
 * }
 * 
 * // Usage in Unity
 * RASPNative.Initialize();
 * int result = RASPNative.CheckSecurity();
 * bool isRooted = RASPNative.IsRootJailbroken();
 * Debug.Log($"Security result: {result}");
 * ```
 */
