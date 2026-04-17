// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Zero-Knowledge TLS Pin Validator — JNI Level
//
// Security properties:
// 1. Expected TLS pins NEVER exist in plaintext in JVM heap or native RAM
// 2. Server cert hash blinded before comparison: SHA256(salt || cert_hash)
// 3. Constant-time comparison prevents timing side-channel attacks
// 4. All intermediates volatile-wiped after use
// 5. Entire pipeline stays in native — invisible to Frida Java hooks

#include "aran_genesis.h"
#include <jni.h>

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_core_AranNative_verifyCertBlinded(
    JNIEnv* env,
    jobject thiz,
    jbyteArray cert_hash
) {
    (void)thiz;

    if (cert_hash == nullptr) return JNI_FALSE;

    jsize hash_len = env->GetArrayLength(cert_hash);
    if (hash_len != 32) return JNI_FALSE;

    // Copy cert hash into native memory (off JVM heap)
    uint8_t native_hash[32];
    env->GetByteArrayRegion(cert_hash, 0, 32, reinterpret_cast<jbyte*>(native_hash));

    // Route to native zero-knowledge blinded verification
    // aran_verify_cert_blinded() blinds the hash with salt and compares
    // against Genesis/Dynamic pins WITHOUT ever decrypting the expected pin
    int result = aran_verify_cert_blinded(native_hash, 32);

    // Wipe the native copy
    aran_secure_wipe(native_hash, sizeof(native_hash));

    return result == 1 ? JNI_TRUE : JNI_FALSE;
}

// JNI function to update dynamic pins from Phantom Channel payload
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_core_AranNative_updateDynamicPins(
    JNIEnv* env,
    jobject thiz,
    jbyteArray pin0_blinded,
    jbyteArray pin1_blinded
) {
    (void)thiz;

    if (pin0_blinded == nullptr || pin1_blinded == nullptr) return;

    jsize len0 = env->GetArrayLength(pin0_blinded);
    jsize len1 = env->GetArrayLength(pin1_blinded);

    if (len0 > ARAN_GENESIS_PIN_LEN) len0 = ARAN_GENESIS_PIN_LEN;
    if (len1 > ARAN_GENESIS_PIN_LEN) len1 = ARAN_GENESIS_PIN_LEN;

    uint8_t p0[ARAN_GENESIS_PIN_LEN], p1[ARAN_GENESIS_PIN_LEN];
    memset(p0, 0, sizeof(p0));
    memset(p1, 0, sizeof(p1));

    env->GetByteArrayRegion(pin0_blinded, 0, len0, reinterpret_cast<jbyte*>(p0));
    env->GetByteArrayRegion(pin1_blinded, 0, len1, reinterpret_cast<jbyte*>(p1));

    aran_update_dynamic_pins(p0, (uint32_t)len0, p1, (uint32_t)len1);

    aran_secure_wipe(p0, sizeof(p0));
    aran_secure_wipe(p1, sizeof(p1));
}
