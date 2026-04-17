/**
 * UNIVERSAL BLACKBOX RASP ENGINE - NativeScript Metadata-Based C++ Headers
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: NativeScript (Android/iOS)
 * Architecture: Metadata-based C++ headers for NativeScript
 */

#ifndef NATIVESCRIPT_RASP_H
#define NATIVESCRIPT_RASP_H

// ============================================
// OBFUSCATED SELECTORS
// ============================================

namespace RASPSelectors {
    static constexpr int FULL_AUDIT = 0x1A2B;
    static constexpr int ROOT_JAILBREAK_ONLY = 0x1A2C;
    static constexpr int DEBUGGER_ONLY = 0x1A2D;
    static constexpr int FRIDA_ONLY = 0x1A2E;
}

namespace RASPStatusTypes {
    static constexpr int ROOT_JAILBREAK = 0x2A2B;
    static constexpr int DEBUGGER = 0x2A2C;
    static constexpr int FRIDA = 0x2A2D;
}

namespace RASPErrorCodes {
    static constexpr int SECURITY_OK = 0x7F3D;
    static constexpr int SUSPICIOUS = 0x7F3C;
    static constexpr int HIGHLY_SUSPICIOUS = 0x7F3B;
    static constexpr int CONFIRMED_TAMPER = 0x7F3A;
}

// ============================================
// NATIVE BRIDGE DECLARATIONS
// ============================================

extern "C" {
    // Native bridge functions
    int rasp_invoke_audit_c(int selector);
    int rasp_get_status_c(int statusType);
    void rasp_initialize_c();
    void rasp_shutdown_c();
}

// ============================================
// NATIVESCRIPT METADATA
// ============================================

/**
 * NativeScript metadata for the RASP module
 * 
 * This metadata is used by NativeScript to generate the JavaScript interface
 * All method names are obfuscated to hide from static analysis
 */

#ifdef __OBJC__

// iOS NativeScript metadata
@interface RASPNativeScript : NSObject

/**
 * Execute security audit
 * @param selector Obfuscated selector value
 * @return Randomized error code from native engine
 */
+ (int)a1_impl:(int)selector;

/**
 * Get detection status
 * @param statusType Obfuscated status type value
 * @return Detection status (0 = not detected, 1 = detected)
 */
+ (int)b2_impl:(int)statusType;

/**
 * Initialize RASP engine
 */
+ (void)d4_impl;

/**
 * Shutdown RASP engine
 */
+ (void)e5_impl;

@end

@implementation RASPNativeScript

+ (int)a1_impl:(int)selector {
    try {
        return rasp_invoke_audit_c(selector);
    } catch (...) {
        return RASPErrorCodes::SECURITY_OK;
    }
}

+ (int)b2_impl:(int)statusType {
    try {
        return rasp_get_status_c(statusType);
    } catch (...) {
        return 0;
    }
}

+ (void)d4_impl {
    try {
        rasp_initialize_c();
    } catch (...) {
        // Silent failure
    }
}

+ (void)e5_impl {
    try {
        rasp_shutdown_c();
    } catch (...) {
        // Silent failure
    }
}

@end

#elif defined(__ANDROID__)

// Android NativeScript metadata
#include <android/log.h>
#include <jni.h>

/**
 * Android NativeScript bridge
 * 
 * This class provides the bridge between NativeScript JavaScript and the native C++ core
 */
class RASPNativeScript {
public:
    /**
     * Execute security audit
     * @param selector Obfuscated selector value
     * @return Randomized error code from native engine
     */
    static int a1_impl(int selector) {
        try {
            return rasp_invoke_audit_c(selector);
        } catch (...) {
            return RASPErrorCodes::SECURITY_OK;
        }
    }

    /**
     * Get detection status
     * @param statusType Obfuscated status type value
     * @return Detection status (0 = not detected, 1 = detected)
     */
    static int b2_impl(int statusType) {
        try {
            return rasp_get_status_c(statusType);
        } catch (...) {
            return 0;
        }
    }

    /**
     * Initialize RASP engine
     */
    static void d4_impl() {
        try {
            rasp_initialize_c();
        } catch (...) {
            // Silent failure
        }
    }

    /**
     * Shutdown RASP engine
     */
    static void e5_impl() {
        try {
            rasp_shutdown_c();
        } catch (...) {
            // Silent failure
        }
    }
};

#endif

// ============================================
// NATIVESCRIPT BINDING CODE
// ============================================

/**
 * NativeScript binding code
 * 
 * This code is used by NativeScript to bind the native functions to JavaScript
 * The binding is done using the NativeScript metadata system
 */

#ifdef __ANDROID__

#include <napi.h>
#include <android/log.h>

#define LOG_TAG "NativeScriptRASP"

/**
 * NativeScript N-API binding for Android
 * 
 * This provides the JavaScript interface for NativeScript on Android
 */
namespace RASPNativeScriptBinding {

/**
 * Execute security audit
 */
static napi_value a1_impl_wrapper(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int selector;
    napi_get_value_int32(env, args[0], &selector);

    int result = RASPNativeScript::a1_impl(selector);

    napi_value jsResult;
    napi_create_int32(env, result, &jsResult);
    return jsResult;
}

/**
 * Get detection status
 */
static napi_value b2_impl_wrapper(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int statusType;
    napi_get_value_int32(env, args[0], &statusType);

    int result = RASPNativeScript::b2_impl(statusType);

    napi_value jsResult;
    napi_create_int32(env, result, &jsResult);
    return jsResult;
}

/**
 * Initialize RASP engine
 */
static napi_value d4_impl_wrapper(napi_env env, napi_callback_info info) {
    RASPNativeScript::d4_impl();
    return nullptr;
}

/**
 * Shutdown RASP engine
 */
static napi_value e5_impl_wrapper(napi_env env, napi_callback_info info) {
    RASPNativeScript::e5_impl();
    return nullptr;
}

/**
 * Initialize the NativeScript module
 */
napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        {"a1_impl", nullptr, a1_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"b2_impl", nullptr, b2_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"d4_impl", nullptr, d4_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"e5_impl", nullptr, e5_impl_wrapper, nullptr, nullptr, napi_default, nullptr}
    };

    napi_define_properties(env, exports, 4, props);
    return exports;
}

} // namespace RASPNativeScriptBinding

NAPI_MODULE(NATIVE_RASP, RASPNativeScriptBinding::Init)

#elif defined(__APPLE__)

#include <node_api.h>

/**
 * NativeScript N-API binding for iOS
 * 
 * This provides the JavaScript interface for NativeScript on iOS
 */
namespace RASPNativeScriptBinding {

/**
 * Execute security audit
 */
static napi_value a1_impl_wrapper(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int selector;
    napi_get_value_int32(env, args[0], &selector);

    int result = [RASPNativeScript a1_impl:selector];

    napi_value jsResult;
    napi_create_int32(env, result, &jsResult);
    return jsResult;
}

/**
 * Get detection status
 */
static napi_value b2_impl_wrapper(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int statusType;
    napi_get_value_int32(env, args[0], &statusType);

    int result = [RASPNativeScript b2_impl:statusType];

    napi_value jsResult;
    napi_create_int32(env, result, &jsResult);
    return jsResult;
}

/**
 * Initialize RASP engine
 */
static napi_value d4_impl_wrapper(napi_env env, napi_callback_info info) {
    [RASPNativeScript d4_impl];
    return nullptr;
}

/**
 * Shutdown RASP engine
 */
static napi_value e5_impl_wrapper(napi_env env, napi_callback_info info) {
    [RASPNativeScript e5_impl];
    return nullptr;
}

/**
 * Initialize the NativeScript module
 */
napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        {"a1_impl", nullptr, a1_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"b2_impl", nullptr, b2_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"d4_impl", nullptr, d4_impl_wrapper, nullptr, nullptr, napi_default, nullptr},
        {"e5_impl", nullptr, e5_impl_wrapper, nullptr, nullptr, napi_default, nullptr}
    };

    napi_define_properties(env, exports, 4, props);
    return exports;
}

} // namespace RASPNativeScriptBinding

NAPI_MODULE(NATIVE_RASP, RASPNativeScriptBinding::Init)

#endif

// ============================================
// USAGE IN NATIVESCRIPT (TypeScript/JavaScript)
// ============================================

/**
 * NativeScript TypeScript/JavaScript usage:
 * 
 * ```typescript
 * import { a1_impl, b2_impl, d4_impl, e5_impl } from 'nativescript-rasp';
 * 
 * // Initialize RASP engine
 * d4_impl();
 * 
 * // Execute security audit
 * const result = a1_impl(0x1A2B);
 * console.log('Security result:', result);
 * 
 * // Get detection status
 * const rootStatus = b2_impl(0x2A2B);
 * const isRooted = rootStatus === 1;
 * if (isRooted) {
 *     console.warn('Root/Jailbreak detected!');
 * }
 * 
 * const debuggerStatus = b2_impl(0x2A2C);
 * const isDebuggerAttached = debuggerStatus === 1;
 * if (isDebuggerAttached) {
 *     console.warn('Debugger detected!');
 * }
 * 
 * const fridaStatus = b2_impl(0x2A2D);
 * const isFridaAttached = fridaStatus === 1;
 * if (isFridaAttached) {
 *     console.warn('Frida detected!');
 * }
 * 
 * // Shutdown RASP engine
 * e5_impl();
 * ```
 * 
 * Or create a higher-level TypeScript wrapper:
 * 
 * ```typescript
 * // rasp-service.ts
 * export class RASPService {
 *     private static instance: RASPService;
 *     private initialized: boolean = false;
 * 
 *     private constructor() {
 *         this.initialize();
 *     }
 * 
 *     static getInstance(): RASPService {
 *         if (!RASPService.instance) {
 *             RASPService.instance = new RASPService();
 *         }
 *         return RASPService.instance;
 *     }
 * 
 *     initialize(): void {
 *         if (!this.initialized) {
 *             d4_impl();
 *             this.initialized = true;
 *         }
 *     }
 * 
 *     shutdown(): void {
 *         if (this.initialized) {
 *             e5_impl();
 *             this.initialized = false;
 *         }
 *     }
 * 
 *     executeAudit(selector: number = 0x1A2B): number {
 *         if (!this.initialized) {
 *             this.initialize();
 *         }
 *         return a1_impl(selector);
 *     }
 * 
 *     getStatus(statusType: number = 0x2A2B): number {
 *         if (!this.initialized) {
 *             this.initialize();
 *         }
 *         return b2_impl(statusType);
 *     }
 * 
 *     checkSecurity(): number {
 *         return this.executeAudit(0x1A2B);
 *     }
 * 
 *     isRootJailbroken(): boolean {
 *         return this.getStatus(0x2A2B) === 1;
 *     }
 * 
 *     isDebuggerAttached(): boolean {
 *         return this.getStatus(0x2A2C) === 1;
 *     }
 * 
 *     isFridaAttached(): boolean {
 *         return this.getStatus(0x2A2D) === 1;
 *     }
 * 
 *     getDetailedStatus(): RASPStatus {
 *         return {
 *             rootJailbreakDetected: this.isRootJailbroken(),
 *             debuggerDetected: this.isDebuggerAttached(),
 *             fridaDetected: this.isFridaAttached(),
 *             securityResult: this.checkSecurity()
 *         };
 *     }
 * }
 * 
 * interface RASPStatus {
 *     rootJailbreakDetected: boolean;
 *     debuggerDetected: boolean;
 *     fridaDetected: boolean;
 *     securityResult: number;
 * }
 * 
 * // Usage in NativeScript app
 * const raspService = RASPService.getInstance();
 * const status = raspService.getDetailedStatus();
 * console.log('Status:', status);
 * ```
 */

#endif // NATIVESCRIPT_RASP_H
