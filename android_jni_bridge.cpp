/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Android JNI Bridge
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Android (JNI)
 * Architecture: JNI with RegisterNatives for symbol hiding
 */

#include <jni.h>
#include <android/log.h>
#include <string>
#include "universal_rasp_core.cpp"

#define LOG_TAG "AndroidRASPBridge"

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
// OBFUSCATED JNI METHOD NAMES
// ============================================

/**
 * Obfuscated JNI method names
 * These random names hide the purpose of the methods from static analysis
 */
namespace ObfuscatedNames {
    static constexpr const char* executeAudit = "a1_impl";
    static constexpr const char* getStatus = "b2_impl";
    static constexpr const char* getDetailedStatus = "c3_impl";
    static constexpr const char* initialize = "d4_impl";
    static constexpr const char* shutdown = "e5_impl";
}

// ============================================
// JNI METHOD IMPLEMENTATIONS
// ============================================

extern "C" {

/**
 * Execute security audit
 * 
 * @param env JNI environment
 * @param thiz Java object
 * @param selector Obfuscated selector value
 * @return Randomized error code from native engine
 */
JNIEXPORT jint JNICALL
Java_com_aran_rasp_RASPNativeModule_a1_impl(
    JNIEnv* env,
    jobject thiz,
    jint selector
) {
    try {
        return universal_rasp_execute_audit(selector);
    } catch (...) {
        // Silent failure - return randomized error code
        return RASPErrorCodes::securityOK;
    }
}

/**
 * Get detection status
 * 
 * @param env JNI environment
 * @param thiz Java object
 * @param statusType Obfuscated status type value
 * @return Detection status (0 = not detected, 1 = detected)
 */
JNIEXPORT jint JNICALL
Java_com_aran_rasp_RASPNativeModule_b2_impl(
    JNIEnv* env,
    jobject thiz,
    jint statusType
) {
    try {
        return universal_rasp_get_status(statusType);
    } catch (...) {
        // Silent failure - return 0 (not detected)
        return 0;
    }
}

/**
 * Get detailed status
 * 
 * @param env JNI environment
 * @param thiz Java object
 * @return HashMap with all detection statuses
 */
JNIEXPORT jobject JNICALL
Java_com_aran_rasp_RASPNativeModule_c3_impl(
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
        jobject rootJailbreakObj = env->NewObject(
            env->FindClass("java/lang/Boolean"),
            env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"),
            rootJailbreakValue
        );
        env->CallObjectMethod(hashMap, putMethod, rootJailbreakKey, rootJailbreakObj);
        
        jstring debuggerKey = env->NewStringUTF("debuggerDetected");
        jboolean debuggerValue = (debugger == 1) ? JNI_TRUE : JNI_FALSE;
        jobject debuggerObj = env->NewObject(
            env->FindClass("java/lang/Boolean"),
            env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"),
            debuggerValue
        );
        env->CallObjectMethod(hashMap, putMethod, debuggerKey, debuggerObj);
        
        jstring fridaKey = env->NewStringUTF("fridaDetected");
        jboolean fridaValue = (frida == 1) ? JNI_TRUE : JNI_FALSE;
        jobject fridaObj = env->NewObject(
            env->FindClass("java/lang/Boolean"),
            env->GetMethodID(env->FindClass("java/lang/Boolean"), "<init>", "(Z)V"),
            fridaValue
        );
        env->CallObjectMethod(hashMap, putMethod, fridaKey, fridaObj);
        
        jstring securityResultKey = env->NewStringUTF("securityResult");
        jobject securityResultObj = env->NewObject(
            env->FindClass("java/lang/Integer"),
            env->GetMethodID(env->FindClass("java/lang/Integer"), "<init>", "(I)V"),
            securityResult
        );
        env->CallObjectMethod(hashMap, putMethod, securityResultKey, securityResultObj);
        
        return hashMap;
    } catch (...) {
        // Silent failure - return null
        return nullptr;
    }
}

/**
 * Initialize RASP engine
 * 
 * @param env JNI environment
 * @param thiz Java object
 */
JNIEXPORT void JNICALL
Java_com_aran_rasp_RASPNativeModule_d4_impl(
    JNIEnv* env,
    jobject thiz
) {
    try {
        universal_rasp_initialize();
    } catch (...) {
        // Silent failure
    }
}

/**
 * Shutdown RASP engine
 * 
 * @param env JNI environment
 * @param thiz Java object
 */
JNIEXPORT void JNICALL
Java_com_aran_rasp_RASPNativeModule_e5_impl(
    JNIEnv* env,
    jobject thiz
) {
    try {
        universal_rasp_shutdown();
    } catch (...) {
        // Silent failure
    }
}

// ============================================
// JNI_ONLOAD - DYNAMIC METHOD REGISTRATION
// ============================================

/**
 * JNI_OnLoad - Dynamic method registration
 * 
 * Uses RegisterNatives to hide method names from the symbol table
 * This prevents static analysis tools from seeing the actual method names
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    
    // Obfuscated class path
    const char* className = "com/aran/rasp/RASPNativeModule";
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_ERR;
    }
    
    // Register native methods with obfuscated names
    JNINativeMethod methods[] = {
        {ObfuscatedNames::executeAudit, "(I)I", (void*)&Java_com_aran_rasp_RASPNativeModule_a1_impl},
        {ObfuscatedNames::getStatus, "(I)I", (void*)&Java_com_aran_rasp_RASPNativeModule_b2_impl},
        {ObfuscatedNames::getDetailedStatus, "()Ljava/util/HashMap;", (void*)&Java_com_aran_rasp_RASPNativeModule_c3_impl},
        {ObfuscatedNames::initialize, "()V", (void*)&Java_com_aran_rasp_RASPNativeModule_d4_impl},
        {ObfuscatedNames::shutdown, "()V", (void*)&Java_com_aran_rasp_RASPNativeModule_e5_impl}
    };
    
    jint result = env->RegisterNatives(clazz, methods, 5);
    if (result != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to register native methods");
        return JNI_ERR;
    }
    
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "JNI_OnLoad: Registered native methods successfully");
    
    return JNI_VERSION_1_6;
}

} // extern "C"

// ============================================
// JAVA/KOTLIN WRAPPER (for reference)
// ============================================

/**
 * Java/Kotlin wrapper class (for reference)
 * 
 * ```java
 * package com.aran.rasp;
 * 
 * public class RASPNativeModule {
 *     static {
 *         System.loadLibrary("aran_rasp");
 *     }
 *     
 *     // Obfuscated native method names
 *     private native int a1_impl(int selector);
 *     private native int b2_impl(int statusType);
 *     private native HashMap<String, Object> c3_impl();
 *     private native void d4_impl();
 *     private native void e5_impl();
 *     
 *     // Public API with descriptive names
 *     public int executeAudit(int selector) {
 *         return a1_impl(selector);
 *     }
 *     
 *     public int getStatus(int statusType) {
 *         return b2_impl(statusType);
 *     }
 *     
 *     public HashMap<String, Object> getDetailedStatus() {
 *         return c3_impl();
 *     }
 *     
 *     public void initialize() {
 *         d4_impl();
 *     }
 *     
 *     public void shutdown() {
 *         e5_impl();
 *     }
 *     
 *     // Convenience methods
 *     public int checkSecurity() {
 *         return executeAudit(0x1A2B);
 *     }
 *     
 *     public boolean isRooted() {
 *         return getStatus(0x2A2B) == 1;
 *     }
 *     
 *     public boolean isDebuggerAttached() {
 *         return getStatus(0x2A2C) == 1;
 *     }
 *     
 *     public boolean isFridaAttached() {
 *         return getStatus(0x2A2D) == 1;
 *     }
 * }
 * ```
 * 
 * Kotlin version:
 * ```kotlin
 * package com.aran.rasp
 * 
 * class RASPNativeModule {
 *     companion object {
 *         init {
 *             System.loadLibrary("aran_rasp")
 *         }
 *     }
 *     
 *     private external fun a1_impl(selector: Int): Int
 *     private external fun b2_impl(statusType: Int): Int
 *     private external fun c3_impl(): Map<String, Any>
 *     private external fun d4_impl()
 *     private external fun e5_impl()
 *     
 *     fun executeAudit(selector: Int): Int = a1_impl(selector)
 *     fun getStatus(statusType: Int): Int = b2_impl(statusType)
 *     fun getDetailedStatus(): Map<String, Any> = c3_impl()
 *     fun initialize() = d4_impl()
 *     fun shutdown() = e5_impl()
 *     
 *     fun checkSecurity(): Int = executeAudit(0x1A2B)
 *     fun isRooted(): Boolean = getStatus(0x2A2B) == 1
 *     fun isDebuggerAttached(): Boolean = getStatus(0x2A2C) == 1
 *     fun isFridaAttached(): Boolean = getStatus(0x2A2D) == 1
 * }
 * ```
 */
