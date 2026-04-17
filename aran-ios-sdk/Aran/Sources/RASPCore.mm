#import <Foundation/Foundation.h>
#include "universal_rasp_core.cpp"

// ============================================
// UNIVERSAL iOS RASP - Objective-C++ Bridge
// BLACKBOX ARCHITECTURE - Static XCFramework
// Works across: Native Swift, Flutter, React Native, Unity
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
@end

@implementation RASPCore

/**
 * Universal audit invocation
 * Selector maps to different security checks:
 * 0 = Full audit
 * 1 = Jailbreak only
 * 2 = Debugger only
 * 3 = Frida only
 */
+ (NSInteger)invokeAudit:(NSInteger)selector {
    // Call the universal C++ function
    return universal_rasp_execute_audit((int)selector);
}

/**
 * Get detection status
 * 0 = Jailbreak
 * 1 = Debugger
 * 2 = Frida
 */
+ (NSInteger)getStatus:(NSInteger)statusType {
    return universal_rasp_get_status((int)statusType);
}

@end

// ============================================
// EXTERN C INTERFACE FOR FRAMEWORK BRIDGES
// ============================================

extern "C" {

/**
 * C-style interface for Flutter/React Native/Unity
 * Easier to bridge from these frameworks
 */
__attribute__((visibility("hidden")))
int rasp_invoke_audit_c(int selector) {
    return [RASPCore invokeAudit:selector];
}

__attribute__((visibility("hidden")))
int rasp_get_status_c(int statusType) {
    return [RASPCore getStatus:statusType];
}

}
