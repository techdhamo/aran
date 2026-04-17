#import <React/RCTBridgeModule.h>
#import <Foundation/Foundation.h>
#include "universal_rasp_core.cpp"

// ============================================
// UNIVERSAL iOS RASP - React Native NativeModule Bridge
// BLACKBOX ARCHITECTURE - Static XCFramework
// ============================================

@interface ReactNativeRASPBridge : NSObject <RCTBridgeModule>
@end

@implementation ReactNativeRASPBridge

RCT_EXPORT_MODULE();

/**
 * Perform security audit
 * - Parameters:
 *   - selector: Audit selector (0 = full, 1 = jailbreak, 2 = debugger, 3 = frida)
 * - Returns: Security result code (0 = OK, 1 = suspicious, 2 = highly suspicious, 3 = confirmed tamper)
 */
RCT_EXPORT_METHOD(performAudit:(NSInteger)selector
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_execute_audit((int)selector);
        resolve(@(result));
    } @catch (NSException *exception) {
        reject(@"PERFORM_AUDIT_ERROR", exception.reason, nil);
    }
}

/**
 * Get detection status
 * - Parameters:
 *   - statusType: Status type (0 = jailbreak, 1 = debugger, 2 = frida)
 * - Returns: Detection status (0 = not detected, 1 = detected)
 */
RCT_EXPORT_METHOD(getStatus:(NSInteger)statusType
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_get_status((int)statusType);
        resolve(@(result));
    } @catch (NSException *exception) {
        reject(@"GET_STATUS_ERROR", exception.reason, nil);
    }
}

/**
 * Convenience method for full security check
 * - Returns: Security result code
 */
RCT_EXPORT_METHOD(checkSecurity:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_execute_audit(0);
        resolve(@(result));
    } @catch (NSException *exception) {
        reject(@"CHECK_SECURITY_ERROR", exception.reason, nil);
    }
}

/**
 * Check if device is jailbroken
 * - Returns: True if jailbreak detected
 */
RCT_EXPORT_METHOD(isJailbroken:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_get_status(0);
        resolve(@(result == 1));
    } @catch (NSException *exception) {
        reject(@"IS_JAILBROKEN_ERROR", exception.reason, nil);
    }
}

/**
 * Check if debugger is attached
 * - Returns: True if debugger detected
 */
RCT_EXPORT_METHOD(isDebuggerAttached:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_get_status(1);
        resolve(@(result == 1));
    } @catch (NSException *exception) {
        reject(@"IS_DEBUGGER_ATTACHED_ERROR", exception.reason, nil);
    }
}

/**
 * Check if Frida is attached
 * - Returns: True if Frida detected
 */
RCT_EXPORT_METHOD(isFridaAttached:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSInteger result = universal_rasp_get_status(2);
        resolve(@(result == 1));
    } @catch (NSException *exception) {
        reject(@"IS_FRIDA_ATTACHED_ERROR", exception.reason, nil);
    }
}

/**
 * Get detailed security status
 * - Returns: Dictionary with all detection statuses
 */
RCT_EXPORT_METHOD(getDetailedStatus:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        NSDictionary *status = @{
            @"jailbreakDetected": @(universal_rasp_get_status(0) == 1),
            @"debuggerDetected": @(universal_rasp_get_status(1) == 1),
            @"fridaDetected": @(universal_rasp_get_status(2) == 1),
            @"securityResult": @(universal_rasp_execute_audit(0))
        };
        resolve(status);
    } @catch (NSException *exception) {
        reject(@"GET_DETAILED_STATUS_ERROR", exception.reason, nil);
    }
}

/**
 * Synchronous version of performAudit (for immediate checks)
 * - Parameters:
 *   - selector: Audit selector
 * - Returns: Security result code
 */
RCT_EXPORT_SYNCHRONOUS_METHOD(NSInteger, performAuditSync:(NSInteger)selector) {
    return universal_rasp_execute_audit((int)selector);
}

/**
 * Synchronous version of isJailbroken (for immediate checks)
 * - Returns: True if jailbreak detected
 */
RCT_EXPORT_SYNCHRONOUS_METHOD(BOOL, isJailbrokenSync) {
    return universal_rasp_get_status(0) == 1;
}

/**
 * Synchronous version of isDebuggerAttached (for immediate checks)
 * - Returns: True if debugger detected
 */
RCT_EXPORT_SYNCHRONOUS_METHOD(BOOL, isDebuggerAttachedSync) {
    return universal_rasp_get_status(1) == 1;
}

/**
 * Synchronous version of isFridaAttached (for immediate checks)
 * - Returns: True if Frida detected
 */
RCT_EXPORT_SYNCHRONOUS_METHOD(BOOL, isFridaAttachedSync) {
    return universal_rasp_get_status(2) == 1;
}

@end

// ============================================
// USAGE IN REACT NATIVE
// ============================================

/**
 * JavaScript/TypeScript usage:
 * 
 * ```typescript
 * import { NativeModules } from 'react-native';
 * const { ReactNativeRASPBridge } = NativeModules;
 * 
 * // Async usage
 * const checkSecurity = async () => {
 *   try {
 *     const result = await ReactNativeRASPBridge.performAudit(0);
 *     console.log('Security result:', result);
 *   } catch (error) {
 *     console.error('Security check failed:', error);
 *   }
 * };
 * 
 * // Sync usage (for immediate checks)
 * const isJailbroken = ReactNativeRASPBridge.isJailbrokenSync();
 * 
 * // Convenience methods
 * const isJailbroken = await ReactNativeRASPBridge.isJailbroken();
 * const isDebuggerAttached = await ReactNativeRASPBridge.isDebuggerAttached();
 * const isFridaAttached = await ReactNativeRASPBridge.isFridaAttached();
 * 
 * // Detailed status
 * const detailedStatus = await ReactNativeRASPBridge.getDetailedStatus();
 * console.log('Detailed status:', detailedStatus);
 * ```
 */
