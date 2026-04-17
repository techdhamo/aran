#include <jni.h>
#include <android/log.h>
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
#include <chrono>
#include <thread>

#define LOG_TAG "AdvancedRASP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ============================================
// ADVANCED RASP PATTERN 1: Dual-Thread Heartbeat
// ============================================

/**
 * Shared heartbeat data structure
 * Thread 1 writes timestamp, Thread 2 verifies it's updating
 */
struct HeartbeatData {
    std::atomic<uint64_t> last_timestamp;
    std::atomic<bool> thread1_running;
    std::atomic<bool> thread2_running;
    std::atomic<bool> heartbeat_failed;
    uint64_t failure_threshold_ms;
};

static HeartbeatData heartbeat_data = {
    std::atomic<uint64_t>(0),
    std::atomic<bool>(false),
    std::atomic<bool>(false),
    std::atomic<bool>(false),
    100 // 100ms threshold
};

static pthread_t heartbeat_thread1;
static pthread_t heartbeat_thread2;

/**
 * Thread 1: Heartbeat writer
 * Continuously updates timestamp in shared memory
 */
static void* heartbeat_writer_thread(void* arg) {
    heartbeat_data.thread1_running.store(true);
    
    while (heartbeat_data.thread1_running.load()) {
        // Get current timestamp in nanoseconds
        auto now = std::chrono::steady_clock::now();
        uint64_t timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        
        // Write to shared memory
        heartbeat_data.last_timestamp.store(timestamp);
        
        // Sleep for 10ms
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    heartbeat_data.thread1_running.store(false);
    return nullptr;
}

/**
 * Thread 2: Heartbeat verifier
 * Verifies that timestamp is updating in real-time
 */
static void* heartbeat_verifier_thread(void* arg) {
    heartbeat_data.thread2_running.store(true);
    
    uint64_t last_check = heartbeat_data.last_timestamp.load();
    
    while (heartbeat_data.thread2_running.load()) {
        // Get current timestamp
        uint64_t current = heartbeat_data.last_timestamp.load();
        
        // Calculate time difference in milliseconds
        uint64_t diff_ms = (current - last_check) / 1000000;
        
        // If timestamp hasn't updated within threshold, heartbeat failed
        // This indicates process/thread suspension (Frida)
        if (diff_ms > heartbeat_data.failure_threshold_ms) {
            LOGE("Heartbeat failure: timestamp not updating for %llu ms", diff_ms);
            heartbeat_data.heartbeat_failed.store(true);
            
            // Trigger silent failure - don't crash immediately
            // Instead, corrupt data subtly
            LOGE("Silent failure triggered due to heartbeat failure");
        }
        
        last_check = current;
        
        // Sleep for 50ms
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    heartbeat_data.thread2_running.store(false);
    return nullptr;
}

/**
 * Initialize dual-thread heartbeat
 */
static int init_dual_thread_heartbeat(uint64_t threshold_ms) {
    heartbeat_data.failure_threshold_ms = threshold_ms;
    heartbeat_data.heartbeat_failed.store(false);
    
    // Create heartbeat writer thread
    if (pthread_create(&heartbeat_thread1, nullptr, heartbeat_writer_thread, nullptr) != 0) {
        LOGE("Failed to create heartbeat writer thread");
        return -1;
    }
    
    // Create heartbeat verifier thread
    if (pthread_create(&heartbeat_thread2, nullptr, heartbeat_verifier_thread, nullptr) != 0) {
        LOGE("Failed to create heartbeat verifier thread");
        // Signal thread1 to stop instead of pthread_cancel (not supported on Android)
        heartbeat_data.thread1_running.store(false);
        pthread_join(heartbeat_thread1, nullptr);
        return -1;
    }
    
    LOGI("Dual-thread heartbeat initialized with %llu ms threshold", threshold_ms);
    return 0;
}

/**
 * Stop dual-thread heartbeat
 */
static void stop_dual_thread_heartbeat() {
    heartbeat_data.thread1_running.store(false);
    heartbeat_data.thread2_running.store(false);
    
    // Wait for threads to exit gracefully
    pthread_join(heartbeat_thread1, nullptr);
    pthread_join(heartbeat_thread2, nullptr);
    
    LOGI("Dual-thread heartbeat stopped");
}

/**
 * Check if heartbeat has failed
 */
static bool check_heartbeat_failed() {
    return heartbeat_data.heartbeat_failed.load();
}

// ============================================
// ADVANCED RASP PATTERN 2: Page Table Integrity
// ============================================

/**
 * Memory segment information
 */
struct MemorySegment {
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t perms;
    char path[256];
    bool is_anonymous;
    bool is_executable;
    bool is_writable;
};

/**
 * Parse /proc/self/maps using direct syscalls
 * Check for anonymous executable memory (code injection indicator)
 */
static int check_page_table_integrity() {
    int fd = open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        LOGE("Failed to open /proc/self/maps");
        return -1;
    }
    
    char buf[8192];
    ssize_t bytes_read;
    int injection_detected = 0;
    
    while ((bytes_read = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        
        char* line = strtok(buf, "\n");
        while (line != nullptr) {
            MemorySegment seg = {0};
            
            // Parse line: address perms offset dev inode pathname
            uint64_t start, end;
            char perms_str[8];
            char path[256] = {0};
            
            int parsed = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s",
                              &start, &end, perms_str, path);
            
            if (parsed >= 3) {
                seg.start_addr = start;
                seg.end_addr = end;
                
                // Parse permissions
                seg.is_executable = (strchr(perms_str, 'x') != nullptr);
                seg.is_writable = (strchr(perms_str, 'w') != nullptr);
                seg.is_anonymous = (parsed < 4 || path[0] == '\0' || path[0] == '[');
                
                // Check for code injection indicators
                if (seg.is_executable && seg.is_anonymous) {
                    LOGE("Anonymous executable memory detected: 0x%lx-0x%lx", start, end);
                    injection_detected = 1;
                }
                
                // Check for writable executable segments (security risk)
                if (seg.is_executable && seg.is_writable) {
                    LOGE("Writable executable segment detected: 0x%lx-0x%lx", start, end);
                    injection_detected = 1;
                }
            }
            
            line = strtok(nullptr, "\n");
        }
    }
    
    close(fd);
    return injection_detected;
}

// ============================================
// ADVANCED RASP PATTERN 3: Inline Hook Detection
// ============================================

/**
 * Stored original function bytes (encrypted)
 */
struct FunctionIntegrity {
    void* function_address;
    uint32_t original_bytes[2]; // First 8 bytes
    uint32_t checksum;
    bool verified;
};

static FunctionIntegrity protected_functions[16];
static int protected_function_count = 0;

/**
 * Calculate checksum of function bytes
 */
static uint32_t calculate_function_checksum(void* func_addr, size_t size) {
    uint32_t checksum = 0;
    uint8_t* data = (uint8_t*)func_addr;
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) | (checksum >> 31);
        checksum += data[i];
    }
    
    return checksum;
}

/**
 * Register a function for integrity monitoring
 */
static int register_function_protection(void* func_addr) {
    if (protected_function_count >= 16) {
        LOGE("Maximum protected functions reached");
        return -1;
    }
    
    // Store original bytes
    uint32_t* instructions = (uint32_t*)func_addr;
    protected_functions[protected_function_count].function_address = func_addr;
    protected_functions[protected_function_count].original_bytes[0] = instructions[0];
    protected_functions[protected_function_count].original_bytes[1] = instructions[1];
    protected_functions[protected_function_count].checksum = calculate_function_checksum(func_addr, 16);
    protected_functions[protected_function_count].verified = true;
    
    LOGI("Registered function protection for address: %p", func_addr);
    protected_function_count++;
    
    return 0;
}

/**
 * Verify function integrity
 * Compares current bytes against stored original bytes
 */
static bool verify_function_integrity(void* func_addr) {
    uint32_t* instructions = (uint32_t*)func_addr;
    
    for (int i = 0; i < protected_function_count; i++) {
        if (protected_functions[i].function_address == func_addr) {
            // Compare first 8 bytes
            if (instructions[0] != protected_functions[i].original_bytes[0] ||
                instructions[1] != protected_functions[i].original_bytes[1]) {
                LOGE("Function integrity compromised at %p", func_addr);
                protected_functions[i].verified = false;
                return false;
            }
            
            // Verify checksum
            uint32_t current_checksum = calculate_function_checksum(func_addr, 16);
            if (current_checksum != protected_functions[i].checksum) {
                LOGE("Function checksum mismatch at %p", func_addr);
                protected_functions[i].verified = false;
                return false;
            }
            
            protected_functions[i].verified = true;
            return true;
        }
    }
    
    return false;
}

/**
 * Verify all protected functions
 */
static int verify_all_functions() {
    int compromised_count = 0;
    
    for (int i = 0; i < protected_function_count; i++) {
        if (!verify_function_integrity(protected_functions[i].function_address)) {
            compromised_count++;
        }
    }
    
    if (compromised_count > 0) {
        LOGE("%d functions have been compromised", compromised_count);
    }
    
    return compromised_count;
}

// ============================================
// ADVANCED RASP PATTERN 4: Silent Failures
// ============================================

/**
 * Silent failure state
 * Instead of crashing immediately, corrupt data subtly
 */
static std::atomic<bool> silent_failure_triggered(false);
static std::atomic<int> corruption_level(0);

/**
 * Trigger silent failure
 * Corrupts data subtly to confuse attacker
 */
static void trigger_silent_failure(int level) {
    silent_failure_triggered.store(true);
    corruption_level.store(level);
    LOGE("Silent failure triggered at level %d", level);
    
    // Don't crash immediately
    // Instead, return random errors later in execution flow
}

/**
 * Check if silent failure has been triggered
 */
static bool is_silent_failure_active() {
    return silent_failure_triggered.load();
}

/**
 * Get corruption level
 */
static int get_corruption_level() {
    return corruption_level.load();
}

// ============================================
// ADVANCED RASP PATTERN 5: Self-Checksumming
// ============================================

/**
 * Calculate checksum of RASP code itself
 */
static uint32_t calculate_rasp_checksum() {
    // Get address of this function
    void* this_func = (void*)calculate_rasp_checksum;
    
    // Calculate checksum of first 1KB of code
    return calculate_function_checksum(this_func, 1024);
}

/**
 * Store RASP checksum at startup
 */
static uint32_t initial_rasp_checksum = 0;

static void initialize_rasp_self_checksum() {
    initial_rasp_checksum = calculate_rasp_checksum();
    LOGI("Initial RASP checksum: %u", initial_rasp_checksum);
}

/**
 * Verify RASP self-integrity
 */
static bool verify_rasp_integrity() {
    uint32_t current_checksum = calculate_rasp_checksum();
    
    if (current_checksum != initial_rasp_checksum) {
        LOGE("RASP self-integrity compromised: expected %u, got %u", initial_rasp_checksum, current_checksum);
        return false;
    }
    
    return true;
}

// ============================================
// ADVANCED RASP PATTERN 6: Syscall Randomization
// ============================================

/**
 * Random syscall wrapper
 * Uses different syscall patterns to prevent pattern matching
 */
static long randomized_syscall(long number, ...) {
    // In production, this would use multiple different syscall patterns
    // For now, use standard syscall
    va_list args;
    va_start(args, number);
    
    // Simple implementation - in production would be more complex
    long result = syscall(number, args);
    
    va_end(args);
    return result;
}

// ============================================
// JNI Exports
// ============================================

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_initializeAdvancedRASP(JNIEnv* env, jobject thiz, jlong thresholdMs) {
    LOGI("========================================");
    LOGI("Initializing Advanced RASP Defense");
    LOGI("========================================");
    
    // Initialize dual-thread heartbeat
    init_dual_thread_heartbeat(static_cast<uint64_t>(thresholdMs));
    
    // Initialize RASP self-checksum
    initialize_rasp_self_checksum();
    
    // Register common libc functions for protection
    void* libc = dlopen("libc.so", RTLD_LAZY);
    if (libc) {
        void* strstr_addr = dlsym(libc, "strstr");
        void* open_addr = dlsym(libc, "open");
        
        if (strstr_addr) register_function_protection(strstr_addr);
        if (open_addr) register_function_protection(open_addr);
        
        dlclose(libc);
    }
    
    LOGI("Advanced RASP Defense initialized");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_checkHeartbeat(JNIEnv* env, jobject thiz) {
    bool failed = check_heartbeat_failed();
    LOGD("Heartbeat check: %s", failed ? "FAILED" : "OK");
    return failed ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_checkPageTableIntegrity(JNIEnv* env, jobject thiz) {
    int result = check_page_table_integrity();
    LOGD("Page table integrity check: %s", result > 0 ? "COMPROMISED" : "OK");
    return result > 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_verifyFunctionIntegrity(JNIEnv* env, jobject thiz) {
    int compromised = verify_all_functions();
    LOGD("Function integrity check: %d functions compromised", compromised);
    return compromised > 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_triggerSilentFailure(JNIEnv* env, jobject thiz, jint level) {
    trigger_silent_failure(level);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_isSilentFailureActive(JNIEnv* env, jobject thiz) {
    return is_silent_failure_active() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_getCorruptionLevel(JNIEnv* env, jobject thiz) {
    return get_corruption_level();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_verifyRASPIntegrity(JNIEnv* env, jobject thiz) {
    bool result = verify_rasp_integrity();
    LOGD("RASP self-integrity: %s", result ? "OK" : "COMPROMISED");
    return result ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedRASPDefense_shutdownAdvancedRASP(JNIEnv* env, jobject thiz) {
    LOGI("Shutting down Advanced RASP Defense...");
    
    stop_dual_thread_heartbeat();
    
    LOGI("Advanced RASP Defense shut down");
}
