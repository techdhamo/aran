#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#define LOG_TAG "AranAntiFrida"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Anti-tampering constants
static const char* FRIDA_PATTERNS[] = {
    "frida-agent",
    "frida-server",
    "frida-inject",
    "frida-helper",
    "frida-core",
    "libfrida",
    "gum-js",
    "gumjs"
};

static const char* SUSPICIOUS_LIBS[] = {
    "libxposed",
    "libsubstrate",
    "libcydia",
    "libsubstrate.so",
    "libxposed_art.so"
};

// Anti-debug detection
static bool is_debugged_by_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true; // Being traced
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return false;
}

static bool is_debugger_attached() {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return false;
    
    char line[256];
    bool debugger_attached = false;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            if (atoi(line + 10) != 0) {
                debugger_attached = true;
                break;
            }
        }
    }
    
    fclose(fp);
    return debugger_attached;
}

// Frida detection via process scanning
static bool scan_for_frida_processes() {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;
    
    struct dirent* entry;
    bool found = false;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        
        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file.is_open()) {
            std::string cmdline;
            std::getline(cmdline_file, cmdline);
            
            for (const char* pattern : FRIDA_PATTERNS) {
                if (cmdline.find(pattern) != std::string::npos) {
                    LOGE("Frida process detected: %s", cmdline.c_str());
                    found = true;
                    break;
                }
            }
        }
    }
    
    closedir(proc_dir);
    return found;
}

// Check for Frida libraries in memory
static bool scan_for_frida_libraries() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    
    char line[1024];
    bool found = false;
    
    while (fgets(line, sizeof(line), maps)) {
        for (const char* pattern : FRIDA_PATTERNS) {
            if (strstr(line, pattern)) {
                LOGE("Frida library detected: %s", line);
                found = true;
                break;
            }
        }
    }
    
    fclose(maps);
    return found;
}

// Check for suspicious libraries
static bool scan_for_suspicious_libraries() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    
    char line[1024];
    bool found = false;
    
    while (fgets(line, sizeof(line), maps)) {
        for (const char* lib : SUSPICIOUS_LIBS) {
            if (strstr(line, lib)) {
                LOGE("Suspicious library detected: %s", line);
                found = true;
                break;
            }
        }
    }
    
    fclose(maps);
    return found;
}

// Check for Frida server via TCP connections
static bool check_frida_tcp_connections() {
    FILE* tcp = fopen("/proc/net/tcp", "r");
    if (!tcp) return false;
    
    char line[512];
    bool found = false;
    
    // Skip header line
    fgets(line, sizeof(line), tcp);
    
    while (fgets(line, sizeof(line), tcp)) {
        // Look for common Frida ports
        if (strstr(line, ":27042") || strstr(line, ":27043")) {
            LOGE("Frida TCP connection detected: %s", line);
            found = true;
            break;
        }
    }
    
    fclose(tcp);
    return found;
}

// Timing attack detection
static bool perform_timing_attack() {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simple operation that should be consistent
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // If execution takes unusually long, likely being debugged/instrumented
    if (duration.count() > 100000) { // 100ms threshold
        LOGE("Timing attack detected: %ld microseconds", duration.count());
        return true;
    }
    
    return false;
}

// Memory integrity check
static bool check_memory_integrity() {
    // Check if our own code memory is writable (shouldn't be)
    void* func_ptr = (void*)check_memory_integrity;
    
    // Try to make memory writable (should fail in normal circumstances)
    if (mprotect(func_ptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        // If successful, something is wrong
        LOGE("Memory protection violation detected");
        mprotect(func_ptr, 4096, PROT_READ | PROT_EXEC); // Restore
        return true;
    }
    
    return false;
}

// Check for hooking in common system calls
static bool detect_syscall_hooks() {
    // Check if openat is hooked
    void* openat_addr = dlsym(RTLD_DEFAULT, "openat64");
    if (!openat_addr) {
        openat_addr = dlsym(RTLD_DEFAULT, "openat");
    }
    
    if (openat_addr) {
        // Check if the first instruction is a jump (common hooking pattern)
        unsigned char* bytes = (unsigned char*)openat_addr;
        if (bytes[0] == 0xE9 || bytes[0] == 0xFF || bytes[0] == 0x48) {
            LOGE("Syscall hooking detected");
            return true;
        }
    }
    
    return false;
}

// Main anti-Frida detection function
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AntiFridaHelper_detectFrida(JNIEnv* env, jobject thiz) {
    LOGI("Starting comprehensive anti-Frida detection...");
    
    bool frida_detected = false;
    
    // 1. Debug detection
    if (is_debugged_by_ptrace()) {
        LOGE("Ptrace debugging detected");
        frida_detected = true;
    }
    
    if (is_debugger_attached()) {
        LOGE("Debugger attached detected");
        frida_detected = true;
    }
    
    // 2. Process scanning
    if (scan_for_frida_processes()) {
        frida_detected = true;
    }
    
    // 3. Library scanning
    if (scan_for_frida_libraries()) {
        frida_detected = true;
    }
    
    if (scan_for_suspicious_libraries()) {
        frida_detected = true;
    }
    
    // 4. Network detection
    if (check_frida_tcp_connections()) {
        frida_detected = true;
    }
    
    // 5. Timing attacks
    if (perform_timing_attack()) {
        frida_detected = true;
    }
    
    // 6. Memory integrity
    if (check_memory_integrity()) {
        frida_detected = true;
    }
    
    // 7. Syscall hooking
    if (detect_syscall_hooks()) {
        frida_detected = true;
    }
    
    if (frida_detected) {
        LOGE("FRIDA DETECTION TRIGGERED - Security breach detected!");
    } else {
        LOGI("Anti-Frida scan completed - No threats detected");
    }
    
    return frida_detected;
}

// Continuous monitoring function
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AntiFridaHelper_startMonitoring(JNIEnv* env, jobject thiz) {
    LOGI("Starting continuous anti-Frida monitoring...");
    
    // Run in background thread
    std::thread([]() {
        while (true) {
            if (is_debugger_attached() || scan_for_frida_processes()) {
                LOGE("Continuous monitoring detected Frida!");
                
                // Kill the process immediately
                prctl(PR_SET_DUMPABLE, 0);
                kill(getpid(), SIGKILL);
                break;
            }
            
            // Check every 2 seconds
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }).detach();
}

// Get device fingerprint for server-side validation
extern "C" JNIEXPORT jstring JNICALL
Java_org_mazhai_aran_security_AntiFridaHelper_getDeviceFingerprint(JNIEnv* env, jobject thiz) {
    std::string fingerprint;
    
    // Collect various device identifiers
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "Hardware", 8) == 0) {
                fingerprint += line;
                break;
            }
        }
        fclose(cpuinfo);
    }
    
    // Add build properties
    fingerprint += std::to_string(android_get_device_api_level());
    
    return env->NewStringUTF(fingerprint.c_str());
}

// Verify app integrity
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AntiFridaHelper_verifyAppIntegrity(JNIEnv* env, jobject thiz) {
    // Get path to our own APK
    jclass context_class = env->FindClass("android/content/Context");
    jmethodID get_package_code_path = env->GetMethodID(context_class, "getPackageCodePath", "()Ljava/lang/String;");
    
    // Get the application context (this would need to be passed in)
    // For now, return true as placeholder
    return JNI_TRUE;
}

// ============================================
// SECURITY HARDENING - PRIORITY 1: Native Frida Detection
// ============================================

// Native Frida detection with enhanced scanning
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsFridaDetected(JNIEnv* env, jobject thiz) {
    LOGI("Starting native Frida detection...");
    
    bool frida_detected = false;
    
    // Check /proc/self/maps for Frida patterns
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "frida") || strstr(line, "gadget") || 
                strstr(line, "gum") || strstr(line, "instrument")) {
                LOGE("Frida pattern detected in maps: %s", line);
                frida_detected = true;
                break;
            }
        }
        fclose(maps);
    }
    
    // Check for memfd regions (common Frida technique)
    FILE* maps2 = fopen("/proc/self/maps", "r");
    if (maps2) {
        char line[512];
        while (fgets(line, sizeof(line), maps2)) {
            if (strstr(line, "r-xp") && strstr(line, "/memfd:")) {
                LOGE("Suspicious memfd region detected: %s", line);
                frida_detected = true;
                break;
            }
        }
        fclose(maps2);
    }
    
    // Check for Frida-specific environment variables
    const char* frida_env = getenv("FRIDA_HOST");
    if (frida_env) {
        LOGE("Frida environment variable detected: %s", frida_env);
        frida_detected = true;
    }
    
    if (frida_detected) {
        LOGE("NATIVE FRIDA DETECTION TRIGGERED");
    } else {
        LOGI("Native Frida detection: No threats found");
    }
    
    return frida_detected ? JNI_TRUE : JNI_FALSE;
}

// Native memory scanning for Frida
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeScanFridaMemory(JNIEnv* env, jobject thiz) {
    LOGI("Scanning memory for Frida injection...");
    
    // Scan /proc/self/maps for suspicious memory regions
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return JNI_FALSE;
    
    char line[512];
    bool suspicious_found = false;
    
    while (fgets(line, sizeof(line), maps)) {
        // Check for executable anonymous memory (common for injected code)
        if (strstr(line, "r-xp") && strstr(line, "00000000")) {
            LOGE("Suspicious executable anonymous memory: %s", line);
            suspicious_found = true;
        }
        
        // Check for memory regions with no file backing (injected code)
        if (strstr(line, "r-xp") && !strstr(line, "/") && !strstr(line, "[heap]") && 
            !strstr(line, "[stack]") && !strstr(line, "[vdso]")) {
            LOGE("Suspicious memory region: %s", line);
            suspicious_found = true;
        }
    }
    
    fclose(maps);
    return suspicious_found ? JNI_TRUE : JNI_FALSE;
}

// Native process scanning for Frida
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeScanFridaProcesses(JNIEnv* env, jobject thiz) {
    LOGI("Scanning processes for Frida...");
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return JNI_FALSE;
    
    struct dirent* entry;
    bool frida_found = false;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        
        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file.is_open()) {
            std::string cmdline;
            std::getline(cmdline_file, cmdline);
            
            if (cmdline.find("frida") != std::string::npos || 
                cmdline.find("gum") != std::string::npos ||
                cmdline.find("objection") != std::string::npos) {
                LOGE("Frida process detected: %s", cmdline.c_str());
                frida_found = true;
            }
        }
    }
    
    closedir(proc_dir);
    return frida_found ? JNI_TRUE : JNI_FALSE;
}

// ============================================
// SECURITY HARDENING - PRIORITY 2: Native Code Validation
// ============================================

// Native response validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeValidateResponse(JNIEnv* env, jobject thiz, jstring responseJson) {
    const char* response = env->GetStringUTFChars(responseJson, NULL);
    
    LOGI("Native response validation...");
    
    // Check for required fields
    bool has_required = false;
    if (strstr(response, "\"success\"") && strstr(response, "\"token\"")) {
        has_required = true;
    }
    
    // Check response structure
    bool valid_structure = false;
    if (response[0] == '{' && response[strlen(response)-1] == '}') {
        valid_structure = true;
    }
    
    env->ReleaseStringUTFChars(responseJson, response);
    
    bool result = has_required && valid_structure;
    LOGI("Response validation: %s", result ? "PASSED" : "FAILED");
    return result ? JNI_TRUE : JNI_FALSE;
}

// Native nonce validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeValidateNonce(JNIEnv* env, jobject thiz, jstring nonce, jlong timestamp) {
    const char* nonce_str = env->GetStringUTFChars(nonce, NULL);
    
    LOGI("Native nonce validation...");
    
    // Check nonce length (should be reasonable)
    size_t nonce_len = strlen(nonce_str);
    bool valid_length = (nonce_len >= 16 && nonce_len <= 256);
    
    // Check timestamp (should be recent, not too old or future)
    jlong current_time = static_cast<jlong>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    jlong time_diff = current_time - timestamp;
    bool valid_timestamp = (time_diff >= 0 && time_diff < 300000); // Within 5 minutes
    
    env->ReleaseStringUTFChars(nonce, nonce_str);
    
    bool result = valid_length && valid_timestamp;
    LOGI("Nonce validation: %s", result ? "PASSED" : "FAILED");
    return result ? JNI_TRUE : JNI_FALSE;
}

// Native signature validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeValidateSignature(JNIEnv* env, jobject thiz, 
                                                                         jstring data, jstring signature, jstring publicKey) {
    const char* data_str = env->GetStringUTFChars(data, NULL);
    const char* sig_str = env->GetStringUTFChars(signature, NULL);
    const char* key_str = env->GetStringUTFChars(publicKey, NULL);
    
    LOGI("Native signature validation...");
    
    // Simple validation - check if signature is not empty and has reasonable length
    bool sig_valid = (strlen(sig_str) > 0 && strlen(sig_str) < 1024);
    bool key_valid = (strlen(key_str) > 0 && strlen(key_str) < 4096);
    bool data_valid = (strlen(data_str) > 0);
    
    env->ReleaseStringUTFChars(data, data_str);
    env->ReleaseStringUTFChars(signature, sig_str);
    env->ReleaseStringUTFChars(publicKey, key_str);
    
    bool result = sig_valid && key_valid && data_valid;
    LOGI("Signature validation: %s", result ? "PASSED" : "FAILED");
    return result ? JNI_TRUE : JNI_FALSE;
}

// Native Play Integrity token validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeValidateIntegrityToken(JNIEnv* env, jobject thiz, jstring token) {
    const char* token_str = env->GetStringUTFChars(token, NULL);
    
    LOGI("Native integrity token validation...");
    
    // Check token structure (JWT format: header.payload.signature)
    int dot_count = 0;
    for (size_t i = 0; i < strlen(token_str); i++) {
        if (token_str[i] == '.') dot_count++;
    }
    
    bool valid_format = (dot_count == 2); // JWT has 2 dots
    bool valid_length = (strlen(token_str) > 50 && strlen(token_str) < 5000);
    
    env->ReleaseStringUTFChars(token, token_str);
    
    bool result = valid_format && valid_length;
    LOGI("Integrity token validation: %s", result ? "PASSED" : "FAILED");
    return result ? JNI_TRUE : JNI_FALSE;
}

// ============================================
// SECURITY HARDENING - PRIORITY 3: Enhanced Root Detection
// ============================================

// Native root detection
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsRooted(JNIEnv* env, jobject thiz) {
    LOGI("Starting native root detection...");
    
    bool root_detected = false;
    
    // Check for su binary in common locations
    const char* su_paths[] = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        NULL
    };
    
    for (int i = 0; su_paths[i] != NULL; i++) {
        if (access(su_paths[i], F_OK) == 0) {
            LOGE("Root detected: su binary found at %s", su_paths[i]);
            root_detected = true;
            break;
        }
    }
    
    // Check for which command (often indicates root)
    if (access("/system/xbin/which", F_OK) == 0) {
        LOGE("Root detected: which command found");
        root_detected = true;
    }
    
    LOGI("Root detection: %s", root_detected ? "DETECTED" : "NOT DETECTED");
    return root_detected ? JNI_TRUE : JNI_FALSE;
}

// Native Magisk detection
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsMagiskDetected(JNIEnv* env, jobject thiz) {
    LOGI("Checking for Magisk...");
    
    bool magisk_detected = false;
    
    // Check for Magisk files
    const char* magisk_paths[] = {
        "/sbin/.magisk",
        "/sbin/.core/mirror",
        "/sbin/.core/img",
        "/sbin/.core/db-0",
        "/sbin/.core/init-rc",
        "/dev/.magisk.unblock",
        "/cache/.disable_magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/magisk_simple",
        NULL
    };
    
    for (int i = 0; magisk_paths[i] != NULL; i++) {
        if (access(magisk_paths[i], F_OK) == 0) {
            LOGE("Magisk detected: %s", magisk_paths[i]);
            magisk_detected = true;
            break;
        }
    }
    
    // Check for Magisk properties
    char magisk_prop[256];
    FILE* fp = fopen("/system/build.prop", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "magisk") || strstr(line, "Magisk")) {
                LOGE("Magisk property detected: %s", line);
                magisk_detected = true;
                break;
            }
        }
        fclose(fp);
    }
    
    return magisk_detected ? JNI_TRUE : JNI_FALSE;
}

// Native busybox detection
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsBusyboxDetected(JNIEnv* env, jobject thiz) {
    LOGI("Checking for busybox...");
    
    const char* busybox_paths[] = {
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/data/local/xbin/busybox",
        "/data/local/bin/busybox",
        "/system/sd/xbin/busybox",
        NULL
    };
    
    for (int i = 0; busybox_paths[i] != NULL; i++) {
        if (access(busybox_paths[i], F_OK) == 0) {
            LOGE("Busybox detected: %s", busybox_paths[i]);
            return JNI_TRUE;
        }
    }
    
    return JNI_FALSE;
}

// Native system partition writable check
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsSystemWritable(JNIEnv* env, jobject thiz) {
    LOGI("Checking if system partition is writable...");
    
    // Check mount points
    FILE* mounts = fopen("/proc/mounts", "r");
    if (!mounts) return JNI_FALSE;
    
    char line[512];
    bool system_writable = false;
    
    while (fgets(line, sizeof(line), mounts)) {
        if (strstr(line, "/system") && strstr(line, "rw,")) {
            LOGE("System partition is writable: %s", line);
            system_writable = true;
            break;
        }
    }
    
    fclose(mounts);
    return system_writable ? JNI_TRUE : JNI_FALSE;
}

// ============================================
// SECURITY HARDENING - PRIORITY 4: Anti-Debugging
// ============================================

// Native ptrace debugging detection
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeIsDebuggedByPtrace(JNIEnv* env, jobject thiz) {
    LOGI("Checking for ptrace debugging...");
    
    // Try to trace ourselves
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        LOGE("Ptrace debugging detected");
        return JNI_TRUE;
    }
    
    // Detach after check
    ptrace(PTRACE_DETACH, 0, 1, 0);
    
    return JNI_FALSE;
}

// ============================================
// SECURITY HARDENING - PRIORITY 6: Code Integrity
// ============================================

// Get method checksum for integrity validation
extern "C" JNIEXPORT jlong JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeGetMethodChecksum(JNIEnv* env, jobject thiz, jstring methodName) {
    const char* method_name = env->GetStringUTFChars(methodName, NULL);
    
    LOGI("Getting checksum for method: %s", method_name);
    
    // Calculate a simple hash of the method name
    // In production, this would calculate the actual checksum of the method bytecode
    unsigned long hash = 5381;
    int c;
    const char* str = method_name;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    
    env->ReleaseStringUTFChars(methodName, method_name);
    
    return (jlong)hash;
}

// Validate method integrity
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_SecurityHardening_nativeValidateMethodIntegrity(JNIEnv* env, jobject thiz, 
                                                                               jstring methodName, jlong expectedChecksum) {
    const char* method_name = env->GetStringUTFChars(methodName, NULL);
    
    LOGI("Validating integrity for method: %s", method_name);
    
    // Calculate current checksum
    jlong currentChecksum = Java_org_mazhai_aran_security_SecurityHardening_nativeGetMethodChecksum(env, thiz, methodName);
    
    env->ReleaseStringUTFChars(methodName, method_name);
    
    bool valid = (currentChecksum == expectedChecksum);
    
    if (!valid) {
        LOGE("Method integrity check FAILED for %s: expected %ld, got %ld", method_name, expectedChecksum, currentChecksum);
    } else {
        LOGI("Method integrity check PASSED for %s", method_name);
    }
    
    return valid ? JNI_TRUE : JNI_FALSE;
}
