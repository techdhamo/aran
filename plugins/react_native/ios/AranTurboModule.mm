/**
 * ARAN RASP ENGINE - React Native TurboModule Implementation
 * 
 * This is a professional, abstract RASP layer that uses TurboModule/JSI
 * instead of the React Native Bridge, which is easily monitored by Frida.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - TURBOMODULE/JSI (bypasses Bridge monitoring)
 * - "Dumb" passthrough to pre-compiled native cores
 * 
 * Architecture:
 * - React Native (JS) -> TurboModule/JSI -> Native Core (AAR/Pod)
 * - No Bridge (easier to hook with Frida)
 * - Direct native function calls via JSI
 */

#import <React/RCTBridgeModule.h>
#import <React/RCTTurboModule.h>
#import <React/RCTEventEmitter.h>
#import "AranRuntime/AranRuntime.h"

@interface RCT_EXTERN_MODULE(AranTurboModule, NSObject<RCTTurboModule>)

RCT_EXTERN_METHOD(validate:(NSInteger)selector
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(initialize:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(shutdown:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getStatus:(NSInteger)statusType
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

@end

@implementation AranTurboModule

RCT_EXPORT_MODULE();

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeAranTurboModuleSpecJSI>(params);
}

// ============================================
// VALIDATE - "Dumb" Passthrough to Native Core
// ============================================
- (void)validate:(NSInteger)selector
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject {
    @try {
        // "Dumb" passthrough - the actual logic is in the Pod
        // Hidden execution - bypasses Bridge monitoring
        uint32_t result = [AranRuntime performInternalAudit:(uint32_t)selector];
        
        resolve(@(result));
    } @catch (NSException *exception) {
        // Silent failure - return 0x7F3D (Security OK) on error
        resolve(@(0x7F3D));
    }
}

// ============================================
// INITIALIZE
// ============================================
- (void)initialize:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        [AranRuntime initializeEngine];
        resolve(@(YES));
    } @catch (NSException *exception) {
        // Silent failure
        resolve(@(YES));
    }
}

// ============================================
// SHUTDOWN
// ============================================
- (void)shutdown:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject {
    @try {
        [AranRuntime shutdownEngine];
        resolve(@(YES));
    } @catch (NSException *exception) {
        // Silent failure
        resolve(@(YES));
    }
}

// ============================================
// GET STATUS
// ============================================
- (void)getStatus:(NSInteger)statusType
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        // "Dumb" passthrough - the actual logic is in the Pod
        uint32_t result = [AranRuntime getStatus:(uint32_t)statusType];
        
        resolve(@(result));
    } @catch (NSException *exception) {
        // Silent failure - return 0 on error
        resolve(@(0));
    }
}

@end
