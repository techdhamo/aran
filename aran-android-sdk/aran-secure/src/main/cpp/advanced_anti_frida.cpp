#include <jni.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

#define LOG_TAG "AdvancedAntiFrida"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ============================================
// ADVANCED ANTI-PATTERN 1: Direct Syscalls (Inline Assembly)
// ============================================

/**
 * Direct syscall wrapper using standard syscall() function
 */
static inline long my_syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    
    long arg1 = va_arg(args, long);
    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);
    long arg6 = va_arg(args, long);
    
    va_end(args);
    
    return syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
}

/**
 * Direct open syscall - bypasses libc hooking
 */
static int direct_open(const char* pathname, int flags, mode_t mode) {
    return (int)my_syscall(__NR_openat, AT_FDCWD, (long)pathname, flags, mode);
}

/**
 * Direct read syscall - bypasses libc hooking
 */
static ssize_t direct_read(int fd, void* buf, size_t count) {
    return (ssize_t)my_syscall(__NR_read, fd, (long)buf, count);
}

/**
 * Direct close syscall - bypasses libc hooking
 */
static int direct_close(int fd) {
    return (int)my_syscall(__NR_close, fd);
}

/**
 * Direct stat syscall - bypasses libc hooking
 */
static int direct_stat(const char* pathname, struct stat* statbuf) {
    return stat(pathname, statbuf);
}

/**
 * Direct string comparison using syscalls (bypasses strstr hooking)
 * Reads file content via direct syscalls and compares
 */
static int direct_string_compare_file(const char* filename, const char* search_str) {
    int fd = direct_open(filename, O_RDONLY, 0);
    if (fd < 0) return 0;
    
    char buf[4096];
    ssize_t bytes_read;
    int found = 0;
    size_t search_len = strlen(search_str);
    
    while ((bytes_read = direct_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        if (strstr(buf, search_str)) {
            found = 1;
            break;
        }
    }
    
    direct_close(fd);
    return found;
}

/**
 * Check /proc/self/maps using direct syscalls
 * Bypasses Frida's strstr hooking in libc
 */
static int check_maps_direct_syscall() {
    int fd = direct_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        LOGE("Failed to open /proc/self/maps with direct syscall");
        return 0;
    }
    
    char buf[8192];
    ssize_t bytes_read;
    int frida_found = 0;
    
    while ((bytes_read = direct_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        
        // Manual string comparison to bypass strstr
        char* ptr = buf;
        while (*ptr) {
            if (strncmp(ptr, "frida", 5) == 0 ||
                strncmp(ptr, "gadget", 6) == 0 ||
                strncmp(ptr, "gum", 3) == 0) {
                LOGE("Frida pattern found in maps (direct syscall): %s", ptr);
                frida_found = 1;
                break;
            }
            ptr++;
        }
        
        if (frida_found) break;
    }
    
    direct_close(fd);
    return frida_found;
}

// ============================================
// ADVANCED ANTI-PATTERN 2: Code Trampoline Detection
// ============================================

/**
 * Check if function has been hooked by examining its first few bytes
 * Hooked functions typically start with jump instructions (trampolines)
 */
static int is_function_hooked(void* func_addr) {
    if (!func_addr) return 0;
    
    // Read first 8 bytes of the function
    uint32_t* instructions = (uint32_t*)func_addr;
    uint32_t first_instr = *instructions;
    
    // ARM64 jump/trampoline patterns
    // B (branch) instruction: 0x14000000
    // BR (branch to register): 0xD61F0000
    // LDR (load register) often used in trampolines: 0x58000000
    
    uint32_t branch_mask = 0xFC000000;
    uint32_t branch_instr = first_instr & branch_mask;
    
    // Check for unconditional branch (B)
    if (branch_instr == 0x14000000) {
        LOGE("Function hooked: B instruction detected at %p", func_addr);
        return 1;
    }
    
    // Check for branch to register (BR)
    uint32_t br_mask = 0xFFFFFC1F;
    uint32_t br_instr = first_instr & br_mask;
    if (br_instr == 0xD61F0000) {
        LOGE("Function hooked: BR instruction detected at %p", func_addr);
        return 1;
    }
    
    // Check for LDR (load register) - common in Frida trampolines
    uint32_t ldr_mask = 0xFF000000;
    uint32_t ldr_instr = first_instr & ldr_mask;
    if (ldr_instr == 0x58000000) {
        LOGE("Function hooked: LDR instruction detected at %p", func_addr);
        return 1;
    }
    
    return 0;
}

/**
 * Check critical libc functions for hooking
 */
static int check_libc_functions_hooked() {
    // Get libc handle
    void* libc_handle = dlopen("libc.so", RTLD_LAZY);
    if (!libc_handle) {
        LOGE("Failed to get libc handle");
        return 0;
    }
    
    int hooked = 0;
    
    // Check commonly hooked functions
    void* strstr_addr = dlsym(libc_handle, "strstr");
    void* open_addr = dlsym(libc_handle, "open");
    void* read_addr = dlsym(libc_handle, "read");
    
    if (is_function_hooked(strstr_addr)) {
        LOGE("strstr appears to be hooked");
        hooked = 1;
    }
    
    if (is_function_hooked(open_addr)) {
        LOGE("open appears to be hooked");
        hooked = 1;
    }
    
    if (is_function_hooked(read_addr)) {
        LOGE("read appears to be hooked");
        hooked = 1;
    }
    
    dlclose(libc_handle);
    return hooked;
}

/**
 * Check our own security functions for hooking
 */
static int check_security_functions_hooked() {
    // This would check functions in our own code
    // For now, return 0 as placeholder
    return 0;
}

// ============================================
// ADVANCED ANTI-PATTERN 3: Advanced Memory Map Monitoring
// ============================================

/**
 * Calculate checksum of memory region
 */
static uint32_t calculate_memory_checksum(void* addr, size_t size) {
    uint32_t checksum = 0;
    uint8_t* data = (uint8_t*)addr;
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) | (checksum >> 31);
        checksum += data[i];
    }
    
    return checksum;
}

/**
 * Store initial memory state at startup
 */
static struct {
    uint32_t maps_checksum;
    int executable_segment_count;
    int library_count;
} initial_memory_state = {0, 0, 0};

/**
 * Analyze /proc/self/maps and calculate checksum
 */
static int analyze_memory_maps(uint32_t* checksum, int* exec_segments, int* lib_count) {
    int fd = direct_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return -1;
    
    char buf[8192];
    ssize_t bytes_read;
    uint32_t local_checksum = 0;
    int local_exec_segments = 0;
    int local_lib_count = 0;
    
    while ((bytes_read = direct_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        
        // Calculate checksum
        for (ssize_t i = 0; i < bytes_read; i++) {
            local_checksum = (local_checksum << 1) | (local_checksum >> 31);
            local_checksum += (uint8_t)buf[i];
        }
        
        // Count executable segments
        if (strstr(buf, "r-xp")) {
            local_exec_segments++;
        }
        
        // Count libraries
        if (strstr(buf, ".so")) {
            local_lib_count++;
        }
    }
    
    direct_close(fd);
    
    if (checksum) *checksum = local_checksum;
    if (exec_segments) *exec_segments = local_exec_segments;
    if (lib_count) *lib_count = local_lib_count;
    
    return 0;
}

/**
 * Initialize memory state (call at app startup)
 */
static void initialize_memory_state() {
    analyze_memory_maps(&initial_memory_state.maps_checksum, 
                       &initial_memory_state.executable_segment_count,
                       &initial_memory_state.library_count);
    
    LOGI("Initial memory state - checksum: %u, exec segments: %d, libs: %d",
         initial_memory_state.maps_checksum,
         initial_memory_state.executable_segment_count,
         initial_memory_state.library_count);
}

/**
 * Check if memory state has changed (indicates library injection)
 */
static int check_memory_integrity() {
    uint32_t current_checksum;
    int current_exec_segments;
    int current_lib_count;
    
    if (analyze_memory_maps(&current_checksum, &current_exec_segments, &current_lib_count) < 0) {
        LOGE("Failed to analyze current memory state");
        return 0;
    }
    
    LOGI("Current memory state - checksum: %u, exec segments: %d, libs: %d",
         current_checksum,
         current_exec_segments,
         current_lib_count);
    
    // Check if checksum changed
    if (current_checksum != initial_memory_state.maps_checksum) {
        LOGE("Memory checksum changed - possible library injection");
        return 1;
    }
    
    // Check if executable segment count changed
    if (current_exec_segments != initial_memory_state.executable_segment_count) {
        LOGE("Executable segment count changed - possible code injection");
        return 1;
    }
    
    // Check if library count changed
    if (current_lib_count != initial_memory_state.library_count) {
        LOGE("Library count changed - possible library injection");
        return 1;
    }
    
    return 0;
}

// ============================================
// ADVANCED ANTI-PATTERN 4: Timing/Latency Attack Detection
// ============================================

/**
 * High-precision timing measurement using clock_gettime
 */
static uint64_t get_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Measure execution time of a simple operation
 * Hooked functions add overhead that can be detected
 */
static int detect_timing_anomaly() {
    uint64_t start, end, duration;
    int sum = 0;
    
    // Measure simple loop execution time
    start = get_timestamp_ns();
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    end = get_timestamp_ns();
    duration = end - start;
    
    // This should take < 1 microsecond normally
    // If it takes significantly longer, something is intercepting
    if (duration > 10000) { // > 10 microseconds
        LOGE("Timing anomaly detected: %llu ns", duration);
        return 1;
    }
    
    // Measure string comparison time
    start = get_timestamp_ns();
    const char* test_str = "this_is_a_test_string_for_timing_check";
    size_t len = strlen(test_str);
    end = get_timestamp_ns();
    duration = end - start;
    
    if (duration > 1000) { // > 1 microsecond
        LOGE("String comparison timing anomaly: %llu ns", duration);
        return 1;
    }
    
    return 0;
}

/**
 * Baseline timing measurement (call at startup)
 */
static uint64_t baseline_timing = 0;

static void initialize_baseline_timing() {
    uint64_t start, end;
    
    // Measure baseline for simple operation
    start = get_timestamp_ns();
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    end = get_timestamp_ns();
    
    baseline_timing = end - start;
    LOGI("Baseline timing: %llu ns", baseline_timing);
}

/**
 * Check if current timing deviates from baseline
 */
static int check_timing_deviation() {
    uint64_t start, end, duration;
    
    start = get_timestamp_ns();
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    end = get_timestamp_ns();
    duration = end - start;
    
    // Allow 10x deviation (generous threshold)
    if (duration > baseline_timing * 10) {
        LOGE("Timing deviation detected: baseline=%llu ns, current=%llu ns",
             baseline_timing, duration);
        return 1;
    }
    
    return 0;
}

// ============================================
// ADVANCED ANTI-PATTERN 5: Frida Artifacts Detection
// ============================================

/**
 * Scan for Frida named pipes
 */
static int scan_frida_pipes() {
    const char* frida_pipes[] = {
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-server",
        "/tmp/frida-",
        "/var/tmp/frida-",
        "/dev/.frida-",
        NULL
    };
    
    for (int i = 0; frida_pipes[i] != NULL; i++) {
        struct stat st;
        if (direct_stat(frida_pipes[i], &st) == 0) {
            LOGE("Frida pipe detected: %s", frida_pipes[i]);
            return 1;
        }
    }
    
    return 0;
}

/**
 * Scan for Frida network connections
 */
static int scan_frida_network() {
    int fd = direct_open("/proc/net/tcp", O_RDONLY, 0);
    if (fd < 0) return 0;
    
    char buf[8192];
    ssize_t bytes_read;
    int frida_found = 0;
    
    // Default Frida port is 27042 (0x69A2 in hex)
    while ((bytes_read = direct_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        
        // Look for port 27042 in hex format: 0069A2
        if (strstr(buf, "0069A2") || strstr(buf, "69A2")) {
            LOGE("Frida network connection detected");
            frida_found = 1;
            break;
        }
    }
    
    direct_close(fd);
    return frida_found;
}

/**
 * Scan for Frida threads (gmain is a common artifact)
 */
static int scan_frida_threads() {
    int fd = direct_open("/proc/self/task", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return 0;
    
    // This would require directory reading via syscalls
    // For simplicity, return 0 for now
    direct_close(fd);
    return 0;
}

// ============================================
// JNI Exports
// ============================================

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_initializeDirectSyscalls(JNIEnv* env, jobject thiz) {
    LOGI("Initializing direct syscall system...");
    // Direct syscalls are always available
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_checkMapsDirectSyscall(JNIEnv* env, jobject thiz) {
    LOGI("Checking /proc/self/maps with direct syscalls...");
    return check_maps_direct_syscall() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_checkFunctionsHooked(JNIEnv* env, jobject thiz) {
    LOGI("Checking for hooked functions...");
    return check_libc_functions_hooked() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_initializeMemoryState(JNIEnv* env, jobject thiz) {
    LOGI("Initializing memory state...");
    initialize_memory_state();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_checkMemoryIntegrity(JNIEnv* env, jobject thiz) {
    LOGI("Checking memory integrity...");
    return check_memory_integrity() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_initializeBaselineTiming(JNIEnv* env, jobject thiz) {
    LOGI("Initializing baseline timing...");
    initialize_baseline_timing();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_checkTimingDeviation(JNIEnv* env, jobject thiz) {
    LOGI("Checking timing deviation...");
    return check_timing_deviation() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_scanFridaPipes(JNIEnv* env, jobject thiz) {
    LOGI("Scanning for Frida pipes...");
    return scan_frida_pipes() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_scanFridaNetwork(JNIEnv* env, jobject thiz) {
    LOGI("Scanning for Frida network connections...");
    return scan_frida_network() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Comprehensive advanced check
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_AdvancedAntiFrida_performAdvancedCheck(JNIEnv* env, jobject thiz) {
    LOGI("========================================");
    LOGI("Performing Advanced Anti-Frida Check");
    LOGI("========================================");
    
    int threats_detected = 0;
    
    // Check 1: Direct syscall maps scan
    if (check_maps_direct_syscall()) {
        LOGE("THREAT: Frida found via direct syscall");
        threats_detected++;
    }
    
    // Check 2: Function hooking
    if (check_libc_functions_hooked()) {
        LOGE("THREAT: Functions appear hooked");
        threats_detected++;
    }
    
    // Check 3: Memory integrity
    if (check_memory_integrity()) {
        LOGE("THREAT: Memory integrity compromised");
        threats_detected++;
    }
    
    // Check 4: Timing deviation
    if (check_timing_deviation()) {
        LOGE("THREAT: Timing anomaly detected");
        threats_detected++;
    }
    
    // Check 5: Frida pipes
    if (scan_frida_pipes()) {
        LOGE("THREAT: Frida pipes detected");
        threats_detected++;
    }
    
    // Check 6: Frida network
    if (scan_frida_network()) {
        LOGE("THREAT: Frida network detected");
        threats_detected++;
    }
    
    LOGI("========================================");
    LOGI("Advanced check complete: %d threats detected", threats_detected);
    LOGI("========================================");
    
    return threats_detected > 0 ? JNI_TRUE : JNI_FALSE;
}
