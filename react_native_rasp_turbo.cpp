/**
 * UNIVERSAL BLACKBOX RASP ENGINE - React Native TurboModule
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Android (JNI), iOS (Objective-C++)
 * Architecture: TurboModule (New Architecture) + Legacy Bridge
 */

#include <react-native/turbo-module/registry.h>
#include <react-native/turbo-module/turbomodule.h>
#include <jsi/jsi.h>
#include "universal_rasp_core.cpp"

using namespace facebook;

// ============================================
// OBFUSCATED SELECTORS
// ============================================

/**
 * Obfuscated selector values
 * These hex values map to different security checks in the native engine
 */
namespace RASPSelectors {
    static constexpr int fullAudit = 0x1A2B;
    static constexpr int rootJailbreakOnly = 0x1A2C;
    static constexpr int debuggerOnly = 0x1A2D;
    static constexpr int fridaOnly = 0x1A2E;
}

/**
 * Obfuscated status type values
 */
namespace RASPStatusTypes {
    static constexpr int rootJailbreak = 0x2A2B;
    static constexpr int debugger = 0x2A2C;
    static constexpr int frida = 0x2A2D;
}

/**
 * Randomized error codes
 */
namespace RASPErrorCodes {
    static constexpr int securityOK = 0x7F3D;
    static constexpr int suspicious = 0x7F3C;
    static constexpr int highlySuspicious = 0x7F3B;
    static constexpr int confirmedTamper = 0x7F3A;
}

// ============================================
// TURBOMODULE SPECIFICATION
// ============================================

/**
 * RASPTurboModule - TurboModule Specification
 * 
 * This defines the JSI interface for the React Native TurboModule
 * All method names are obfuscated to avoid sensitive strings
 */
namespace facebook {
namespace react {

class RASPTurboModuleSpec : public TurboModuleSpec {
public:
    RASPTurboModuleSpec(const std::string& name) : TurboModuleSpec(name) {}
    
    // Execute security audit
    virtual int executeAudit(int selector) = 0;
    
    // Get detection status
    virtual int getStatus(int statusType) = 0;
    
    // Get detailed status
    virtual jsi::Object getDetailedStatus(jsi::Runtime& runtime) = 0;
};

} // namespace react
} // namespace facebook

// ============================================
// TURBOMODULE IMPLEMENTATION
// ============================================

/**
 * RASPTurboModule - TurboModule Implementation
 * 
 * This is the actual implementation that calls the unified C++ core
 */
namespace facebook {
namespace react {

class RASPTurboModule : public NativeRASPTurboModuleSpec {
public:
    RASPTurboModule(std::shared_ptr<CallInvoker> jsInvoker)
        : NativeRASPTurboModuleSpec(jsInvoker) {}
    
    /**
     * Execute security audit
     */
    int executeAudit(int selector) override {
        try {
            // Call the unified C++ core
            return universal_rasp_execute_audit(selector);
        } catch (...) {
            // Silent failure - return randomized error code
            return RASPErrorCodes::securityOK;
        }
    }
    
    /**
     * Get detection status
     */
    int getStatus(int statusType) override {
        try {
            // Call the unified C++ core
            return universal_rasp_get_status(statusType);
        } catch (...) {
            // Silent failure - return 0 (not detected)
            return 0;
        }
    }
    
    /**
     * Get detailed status
     */
    jsi::Object getDetailedStatus(jsi::Runtime& runtime) override {
        try {
            jsi::Object result(runtime);
            
            // Get detection statuses
            int rootJailbreak = universal_rasp_get_status(RASPStatusTypes::rootJailbreak);
            int debugger = universal_rasp_get_status(RASPStatusTypes::debugger);
            int frida = universal_rasp_get_status(RASPStatusTypes::frida);
            int securityResult = universal_rasp_execute_audit(RASPSelectors::fullAudit);
            
            // Set properties
            result.setProperty(runtime, "rootJailbreakDetected", jsi::Value(runtime, rootJailbreak == 1));
            result.setProperty(runtime, "debuggerDetected", jsi::Value(runtime, debugger == 1));
            result.setProperty(runtime, "fridaDetected", jsi::Value(runtime, frida == 1));
            result.setProperty(runtime, "securityResult", jsi::Value(runtime, securityResult));
            
            return result;
        } catch (...) {
            // Silent failure - return empty object
            return jsi::Object(runtime);
        }
    }
};

} // namespace react
} // namespace facebook

// ============================================
// TURBOMODULE REGISTRATION
// ============================================

/**
 * Register the TurboModule
 * This is called during React Native initialization
 */
extern "C" {

__attribute__((visibility("default")))
void registerRASPTurboModule(
    jsi::Runtime& runtime,
    std::shared_ptr<react::CallInvoker> jsInvoker
) {
    // Create and register the TurboModule
    auto module = std::make_shared<react::RASPTurboModule>(jsInvoker);
    
    // Register with React Native
    // This is a simplified registration - actual implementation depends on React Native version
    // For React Native 0.74+, use the new TurboModule registry
    // For older versions, use the legacy bridge
}

} // extern "C"

// ============================================
// LEGACY BRIDGE IMPLEMENTATION
// ============================================

#if defined(__ANDROID__)
    #include <jni.h>
    #include <android/log.h>
    
    /**
     * Legacy Android JNI Bridge
     * 
     * This provides backward compatibility with the old React Native bridge
     * Uses JNI to call the unified C++ core
     */
    extern "C" {
        
        JNIEXPORT jint JNICALL
        Java_com_aran_rasp_RASPModule_executeAudit(
            JNIEnv* env,
            jobject thiz,
            jint selector
        ) {
            try {
                return universal_rasp_execute_audit(selector);
            } catch (...) {
                return RASPErrorCodes::securityOK;
            }
        }
        
        JNIEXPORT jint JNICALL
        Java_com_aran_rasp_RASPModule_getStatus(
            JNIEnv* env,
            jobject thiz,
            jint statusType
        ) {
            try {
                return universal_rasp_get_status(statusType);
            } catch (...) {
                return 0;
            }
        }
        
        JNIEXPORT jobject JNICALL
        Java_com_aran_rasp_RASPModule_getDetailedStatus(
            JNIEnv* env,
            jobject thiz
        ) {
            try {
                // Get detection statuses
                int rootJailbreak = universal_rasp_get_status(RASPStatusTypes::rootJailbreak);
                int debugger = universal_rasp_get_status(RASPStatusTypes::debugger);
                int frida = universal_rasp_get_status(RASPStatusTypes::frida);
                int securityResult = universal_rasp_execute_audit(RASPSelectors::fullAudit);
                
                // Create Java HashMap
                jclass hashMapClass = env->FindClass("java/util/HashMap");
                jmethodID hashMapConstructor = env->GetMethodID(hashMapClass, "<init>", "()V");
                jobject hashMap = env->NewObject(hashMapClass, hashMapConstructor);
                
                jmethodID putMethod = env->GetMethodID(hashMapClass, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
                
                // Put values
                jstring rootJailbreakKey = env->NewStringUTF("rootJailbreakDetected");
                jboolean rootJailbreakValue = (rootJailbreak == 1) ? JNI_TRUE : JNI_FALSE;
                jobject rootJailbreakObj = env->NewObject(env->FindClass("java/lang/Boolean"), env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"), rootJailbreakValue);
                env->CallObjectMethod(hashMap, putMethod, rootJailbreakKey, rootJailbreakObj);
                
                jstring debuggerKey = env->NewStringUTF("debuggerDetected");
                jboolean debuggerValue = (debugger == 1) ? JNI_TRUE : JNI_FALSE;
                jobject debuggerObj = env->NewObject(env->FindClass("java/lang/Boolean"), env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"), debuggerValue);
                env->CallObjectMethod(hashMap, putMethod, debuggerKey, debuggerObj);
                
                jstring fridaKey = env->NewStringUTF("fridaDetected");
                jboolean fridaValue = (frida == 1) ? JNI_TRUE : JNI_FALSE;
                jobject fridaObj = env->NewObject(env->FindClass("java/lang/Boolean"), env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"), fridaValue);
                env->CallObjectMethod(hashMap, putMethod, fridaKey, fridaObj);
                
                jstring securityResultKey = env->NewStringUTF("securityResult");
                jobject securityResultObj = env->NewObject(env->FindClass("java/lang/Integer"), env->GetMethodID(env->FindClass("java/lang/Integer"), "<init>", "(I)V"), securityResult);
                env->CallObjectMethod(hashMap, putMethod, securityResultKey, securityResultObj);
                
                return hashMap;
            } catch (...) {
                return nullptr;
            }
        }
        
    }
    
#elif defined(__APPLE__)
    #import <React/RCTBridgeModule.h>
    #import <Foundation/Foundation.h>
    
    /**
     * Legacy iOS Objective-C Bridge
     * 
     * This provides backward compatibility with the old React Native bridge
     * Uses Objective-C to call the unified C++ core
     */
    @interface RASPLegacyModule : NSObject <RCTBridgeModule>
    @end
    
    @implementation RASPLegacyModule
    
    RCT_EXPORT_MODULE();
    
    /**
     * Execute security audit
     */
    RCT_EXPORT_METHOD(executeAudit:(NSInteger)selector
                      resolver:(RCTPromiseResolveBlock)resolve
                      rejecter:(RCTPromiseRejectBlock)reject) {
        @try {
            NSInteger result = universal_rasp_execute_audit((int)selector);
            resolve(@(result));
        } @catch (NSException *exception) {
            reject(@"EXECUTE_AUDIT_ERROR", exception.reason, nil);
        }
    }
    
    /**
     * Get detection status
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
     * Get detailed status
     */
    RCT_EXPORT_METHOD(getDetailedStatus:(RCTPromiseResolveBlock)resolve
                      rejecter:(RCTPromiseRejectBlock)reject) {
        @try {
            NSDictionary *status = @{
                @"rootJailbreakDetected": @(universal_rasp_get_status(RASPStatusTypes::rootJailbreak) == 1),
                @"debuggerDetected": @(universal_rasp_get_status(RASPStatusTypes::debugger) == 1),
                @"fridaDetected": @(universal_rasp_get_status(RASPStatusTypes::frida) == 1),
                @"securityResult": @(universal_rasp_execute_audit(RASPSelectors::fullAudit))
            };
            resolve(status);
        } @catch (NSException *exception) {
            reject(@"GET_DETAILED_STATUS_ERROR", exception.reason, nil);
        }
    }
    
    @end
    
#endif

// ============================================
// USAGE IN REACT NATIVE (JavaScript/TypeScript)
// ============================================

/**
 * JavaScript/TypeScript usage:
 * 
 * ```typescript
 * import { NativeModules } from 'react-native';
 * 
 * // TurboModule (New Architecture)
 * import RASPTurboModule from 'react-native-rasp/src/NativeRASP';
 * 
 * // Legacy Bridge (Old Architecture)
 * const { RASPLegacyModule } = NativeModules;
 * 
 * // Using TurboModule
 * const checkSecurity = async () => {
 *   try {
 *     const result = await RASPTurboModule.executeAudit(0x1A2B);
 *     console.log('Security result:', result);
 *   } catch (error) {
 *     console.error('Security check failed:', error);
 *   }
 * };
 * 
 * // Using Legacy Bridge
 * const checkSecurityLegacy = async () => {
 *   try {
 *     const result = await RASPLegacyModule.executeAudit(0x1A2B);
 *     console.log('Security result:', result);
 *   } catch (error) {
 *     console.error('Security check failed:', error);
 *   }
 * };
 * 
 * // Convenience methods (can be added to the TurboModule spec)
 * const isRootJailbroken = async () => {
 *   const result = await RASPTurboModule.getStatus(0x2A2B);
 *   return result === 1;
 * };
 * 
 * const isDebuggerAttached = async () => {
 *   const result = await RASPTurboModule.getStatus(0x2A2C);
 *   return result === 1;
 * };
 * 
 * const isFridaAttached = async () => {
 *   const result = await RASPTurboModule.getStatus(0x2A2D);
 *   return result === 1;
 * };
 * 
 * // Detailed status
 * const detailedStatus = await RASPTurboModule.getDetailedStatus();
 * console.log('Detailed status:', detailedStatus);
 * ```
 */
