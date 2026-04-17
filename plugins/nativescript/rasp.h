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

extern "C" {
    int rasp_invoke_audit_c(int selector);
    int rasp_get_status_c(int statusType);
    void rasp_initialize_c();
    void rasp_shutdown_c();
}

#ifdef __OBJC__

@interface RASPNativeScript : NSObject
+ (int)a1_impl:(int)selector;
+ (int)b2_impl:(int)statusType;
+ (void)d4_impl;
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
    }
}

+ (void)e5_impl {
    try {
        rasp_shutdown_c();
    } catch (...) {
    }
}

@end

#elif defined(__ANDROID__)

#include <android/log.h>
#include <jni.h>

class RASPNativeScript {
public:
    static int a1_impl(int selector) {
        try {
            return rasp_invoke_audit_c(selector);
        } catch (...) {
            return RASPErrorCodes::SECURITY_OK;
        }
    }

    static int b2_impl(int statusType) {
        try {
            return rasp_get_status_c(statusType);
        } catch (...) {
            return 0;
        }
    }

    static void d4_impl() {
        try {
            rasp_initialize_c();
        } catch (...) {
        }
    }

    static void e5_impl() {
        try {
            rasp_shutdown_c();
        } catch (...) {
        }
    }
};

#endif

#ifdef __ANDROID__

#include <napi.h>

namespace RASPNativeScriptBinding {

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

static napi_value d4_impl_wrapper(napi_env env, napi_callback_info info) {
    RASPNativeScript::d4_impl();
    return nullptr;
}

static napi_value e5_impl_wrapper(napi_env env, napi_callback_info info) {
    RASPNativeScript::e5_impl();
    return nullptr;
}

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

}

NAPI_MODULE(NATIVE_RASP, RASPNativeScriptBinding::Init)

#elif defined(__APPLE__)

#include <node_api.h>

namespace RASPNativeScriptBinding {

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

static napi_value d4_impl_wrapper(napi_env env, napi_callback_info info) {
    [RASPNativeScript d4_impl];
    return nullptr;
}

static napi_value e5_impl_wrapper(napi_env env, napi_callback_info info) {
    [RASPNativeScript e5_impl];
    return nullptr;
}

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

}

NAPI_MODULE(NATIVE_RASP, RASPNativeScriptBinding::Init)

#endif

#endif // NATIVESCRIPT_RASP_H
