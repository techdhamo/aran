// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ============================================================================
// Scorched Earth Native — Network Blackhole
// ============================================================================
//
// Sets a volatile C-level flag that all network operations check.
// Once set, aran_is_network_allowed() returns false, causing all
// HTTP/TLS operations to fail immediately.
//
// This is the SEVER phase of the Scorched Earth protocol.

#include <jni.h>
#include <atomic>

// Volatile prevents dead-store elimination by the compiler.
// Even if an attacker attaches with Frida after the flag is set,
// the volatile ensures the check sees the true value.
static volatile std::atomic<int> g_aran_is_compromised{0};

extern "C" {

/**
 * Returns true if network operations should be blocked.
 * Called by OkHttp interceptors and native TLS handshake.
 */
int aran_is_network_allowed() {
    return g_aran_is_compromised.load(std::memory_order_acquire) == 0 ? 1 : 0;
}

/**
 * Sets the compromised flag. Irreversible for this process lifetime.
 */
void aran_set_compromised_flag() {
    g_aran_is_compromised.store(1, std::memory_order_release);
}

/**
 * Resets the flag (testing only — never call in production).
 */
void aran_reset_compromised_flag() {
    g_aran_is_compromised.store(0, std::memory_order_release);
}

// ============================================================================
// JNI Bridge
// ============================================================================

JNIEXPORT void JNICALL
Java_org_mazhai_aran_core_AranNative_nativeSetCompromisedFlag(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    aran_set_compromised_flag();
}

} // extern "C"
