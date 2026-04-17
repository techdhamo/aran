/**
 * ANDROID JNI BRIDGE FOR ARAN RASP ENGINE
 * 
 * This file provides JNI bindings for the C++ RASP core engine.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 */

#include <jni.h>
#include <string>
#include <android/log.h>

#define LOG_TAG "ARAN_RASP"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================
// EXTERNAL C++ CORE ENGINE
// ============================================

extern "C" {
    // These functions are defined in the universal RASP core
    int rasp_execute_audit_c(int selector);
    int rasp_get_status_c(int statusType);
    void rasp_initialize_c();
    void rasp_shutdown_c();
}

// ============================================
// JNI BINDINGS
// ============================================

extern "C" JNIEXPORT jint JNICALL
Java_com_aran_security_rasp_RASPNativeModule_executeAudit(JNIEnv* env, jobject thiz, jint selector) {
    try {
        return rasp_execute_audit_c(selector);
    } catch (...) {
        LOGE("Exception in executeAudit");
        return 0x7F3D; // Security OK (silent failure)
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_aran_security_rasp_RASPNativeModule_getStatus(JNIEnv* env, jobject thiz, jint statusType) {
    try {
        return rasp_get_status_c(statusType);
    } catch (...) {
        LOGE("Exception in getStatus");
        return 0; // Silent failure
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_aran_security_rasp_RASPNativeModule_initialize(JNIEnv* env, jobject thiz) {
    try {
        rasp_initialize_c();
    } catch (...) {
        LOGE("Exception in initialize");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_aran_security_rasp_RASPNativeModule_shutdown(JNIEnv* env, jobject thiz) {
    try {
        rasp_shutdown_c();
    } catch (...) {
        LOGE("Exception in shutdown");
    }
}
