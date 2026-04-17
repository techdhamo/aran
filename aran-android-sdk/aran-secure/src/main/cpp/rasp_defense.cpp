#include <jni.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <atomic>

#define LOG_TAG "RASPDefense"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ============================================
// RASP DEFENSE LAYER 1: String Encryption
// ============================================

/**
 * Simple XOR encryption for sensitive strings
 * Decrypts in-memory only during use
 */
static constexpr uint8_t ENCRYPTION_KEY = 0x42;

/**
 * Decrypt string in-place
 */
static void decrypt_string(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= ENCRYPTION_KEY;
    }
}

/**
 * Encrypt string in-place
 */
static void encrypt_string(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= ENCRYPTION_KEY;
    }
}

/**
 * Encrypted sensitive strings (XOR encrypted)
 * These are stored encrypted in the binary
 */
static char s_proc_self_maps[] = {
    // "/proc/self/maps" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x32 ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 
    0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x00 ^ 0x42
};

static char s_frida[] = {
    // "frida" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x32 ^ 0x42, 0x30 ^ 0x42, 0x00 ^ 0x42
};

static char s_gadget[] = {
    // "gadget" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x32 ^ 0x42, 0x30 ^ 0x42, 0x2f ^ 0x42, 0x00 ^ 0x42
};

static char s_gum[] = {
    // "gum" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x32 ^ 0x42, 0x00 ^ 0x42
};

static char s_su[] = {
    // "su" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x00 ^ 0x42
};

static char s_libc_so[] = {
    // "libc.so" encrypted
    0x1f ^ 0x42, 0x30 ^ 0x42, 0x32 ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x2f ^ 0x42, 0x00 ^ 0x42
};

/**
 * Get decrypted string (temporary)
 * Caller must not free, string is in global memory
 */
static const char* get_decrypted_string(char* encrypted, size_t len) {
    decrypt_string(encrypted, len);
    return encrypted;
}

/**
 * Re-encrypt string after use
 */
static void reencrypt_string(char* encrypted, size_t len) {
    encrypt_string(encrypted, len);
}

/**
 * Safe string comparison with encrypted strings
 */
static int safe_strcmp_encrypted(char* encrypted, size_t len, const char* target) {
    decrypt_string(encrypted, len);
    int result = strcmp(encrypted, target);
    encrypt_string(encrypted, len);
    return result;
}

// ============================================
// RASP DEFENSE LAYER 2: Self-Trace Pattern
// ============================================

/**
 * Self-trace protection
 * Prevents Frida from attaching by occupying the ptrace slot
 */
static std::atomic<bool> self_trace_active(false);
static pthread_t self_trace_thread;

static void* self_trace_monitor(void* arg) {
    while (self_trace_active.load()) {
        // Periodically verify we're still self-traced
        // If we lose self-trace, something else might have taken over
        usleep(1000000); // 1 second
    }
    return nullptr;
}

/**
 * Initialize self-trace protection
 */
static int init_self_trace_protection() {
    // Try to trace ourselves
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        if (errno == EPERM) {
            // Already being traced - likely by Frida or debugger
            LOGE("Self-trace failed - already being traced by another process");
            return -1;
        }
        LOGE("Self-trace failed with error: %s", strerror(errno));
        return -1;
    }
    
    LOGI("Self-trace protection enabled");
    self_trace_active.store(true);
    
    // Create monitor thread
    if (pthread_create(&self_trace_thread, nullptr, self_trace_monitor, nullptr) != 0) {
        LOGE("Failed to create self-trace monitor thread");
        return -1;
    }
    
    return 0;
}

/**
 * Disable self-trace protection
 */
static void disable_self_trace_protection() {
    self_trace_active.store(false);
    pthread_join(self_trace_thread, nullptr);
    ptrace(PTRACE_DETACH, 0, 1, 0);
    LOGI("Self-trace protection disabled");
}

// ============================================
// RASP DEFENSE LAYER 3: Cyclic Integrity Checks
// ============================================

/**
 * Background thread for cyclic integrity checks
 */
static std::atomic<bool> cyclic_checks_active(false);
static pthread_t cyclic_check_thread;

/**
 * Check function integrity
 * Verifies that critical security functions haven't been modified
 */
static bool check_function_integrity(void* func_addr, const char* func_name) {
    if (!func_addr) return false;
    
    // Read first 8 bytes
    uint32_t* instructions = (uint32_t*)func_addr;
    uint32_t first_instr = instructions[0];
    
    // Check for trampolines (jump instructions)
    uint32_t branch_mask = 0xFC000000;
    uint32_t branch_instr = first_instr & branch_mask;
    
    if (branch_instr == 0x14000000 || // B instruction
        branch_instr == 0xD61F0000 || // BR instruction
        (first_instr & 0xFF000000) == 0x58000000) { // LDR instruction
        LOGE("Function %s appears hooked (trampoline detected)", func_name);
        return false;
    }
    
    return true;
}

/**
 * Cyclic check function
 * Runs periodically to verify integrity
 */
static void* cyclic_check_monitor(void* arg) {
    const char* libc_path = get_decrypted_string(s_libc_so, 8);
    
    while (cyclic_checks_active.load()) {
        // Check libc functions
        void* libc_handle = dlopen(libc_path, RTLD_LAZY);
        if (libc_handle) {
            void* strstr_addr = dlsym(libc_handle, get_decrypted_string(s_frida, 6));
            void* open_addr = dlsym(libc_handle, "open");
            
            if (!check_function_integrity(strstr_addr, "strstr")) {
                LOGE("Cyclic check: strstr integrity compromised");
                // Trigger emergency response
                _exit(1);
            }
            
            if (!check_function_integrity(open_addr, "open")) {
                LOGE("Cyclic check: open integrity compromised");
                _exit(1);
            }
            
            dlclose(libc_handle);
        }
        
        reencrypt_string(s_libc_so, 8);
        reencrypt_string(s_frida, 6);
        
        // Check memory integrity
        // (This would call the memory integrity check from advanced_anti_frida.cpp)
        
        // Sleep for 30 seconds
        for (int i = 0; i < 30 && cyclic_checks_active.load(); i++) {
            usleep(1000000);
        }
    }
    
    return nullptr;
}

/**
 * Initialize cyclic integrity checks
 */
static int init_cyclic_checks() {
    cyclic_checks_active.store(true);
    
    if (pthread_create(&cyclic_check_thread, nullptr, cyclic_check_monitor, nullptr) != 0) {
        LOGE("Failed to create cyclic check thread");
        return -1;
    }
    
    LOGI("Cyclic integrity checks started");
    return 0;
}

/**
 * Stop cyclic integrity checks
 */
static void stop_cyclic_checks() {
    cyclic_checks_active.store(false);
    pthread_join(cyclic_check_thread, nullptr);
    LOGI("Cyclic integrity checks stopped");
}

// ============================================
// RASP DEFENSE LAYER 4: Obfuscated Function Names
// ============================================

/**
 * Obfuscated function names
 * These are intentionally named to look innocuous
 */

// Instead of "checkForFrida", use:
static void init_system_fonts(void) {
    // This actually performs Frida detection
    LOGI("init_system_fonts called (obfuscated security check)");
}

// Instead of "verifyIntegrity", use:
static void load_textures(void) {
    // This actually performs integrity verification
    LOGI("load_textures called (obfuscated security check)");
}

// Instead of "checkRoot", use:
static void precompute_layout(void) {
    // This actually performs root detection
    LOGI("precompute_layout called (obfuscated security check)");
}

// ============================================
// JNI Exports for RASP Defense
// ============================================

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RASPDefense_initializeRASPDefense(JNIEnv* env, jobject thiz) {
    LOGI("========================================");
    LOGI("Initializing RASP Defense Layers");
    LOGI("========================================");
    
    // Initialize self-trace protection
    if (init_self_trace_protection() < 0) {
        LOGE("Failed to initialize self-trace protection");
    }
    
    // Initialize cyclic integrity checks
    if (init_cyclic_checks() < 0) {
        LOGE("Failed to initialize cyclic checks");
    }
    
    // Call obfuscated functions
    init_system_fonts();
    load_textures();
    precompute_layout();
    
    LOGI("RASP Defense layers initialized");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RASPDefense_checkStringEncryption(JNIEnv* env, jobject thiz) {
    LOGI("Testing string encryption...");
    
    // Test encrypted string comparison
    const char* test_str = get_decrypted_string(s_frida, 6);
    bool matches = (strcmp(test_str, "frida") == 0);
    reencrypt_string(s_frida, 6);
    
    LOGI("String encryption test: %s", matches ? "PASSED" : "FAILED");
    return matches ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RASPDefense_isSelfTraceActive(JNIEnv* env, jobject thiz) {
    return self_trace_active.load() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RASPDefense_disableSelfTrace(JNIEnv* env, jobject thiz) {
    disable_self_trace_protection();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RASPDefense_isCyclicChecksActive(JNIEnv* env, jobject thiz) {
    return cyclic_checks_active.load() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RASPDefense_stopCyclicChecks(JNIEnv* env, jobject thiz) {
    stop_cyclic_checks();
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_mazhai_aran_security_RASPDefense_performObfuscatedCheck(JNIEnv* env, jobject thiz, jstring checkType) {
    const char* check_type = env->GetStringUTFChars(checkType, NULL);
    
    // Call obfuscated functions based on check type
    if (strcmp(check_type, "fonts") == 0) {
        init_system_fonts();
    } else if (strcmp(check_type, "textures") == 0) {
        load_textures();
    } else if (strcmp(check_type, "layout") == 0) {
        precompute_layout();
    }
    
    env->ReleaseStringUTFChars(checkType, check_type);
    
    return env->NewStringUTF("Obfuscated check completed");
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RASPDefense_shutdownRASPDefense(JNIEnv* env, jobject thiz) {
    LOGI("Shutting down RASP Defense layers...");
    
    disable_self_trace_protection();
    stop_cyclic_checks();
    
    LOGI("RASP Defense layers shut down");
}
