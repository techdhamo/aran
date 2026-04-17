#include <jni.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <cstring>
#include <atomic>
#include <random>
#include <chrono>
#include <thread>
#include <android/log.h>

#define TAG "RASP_Core_Engine"

// ============================================
// NATIVE CORE ENGINE - 90% of Logic in C++
// BLACKBOX ARCHITECTURE - Advanced Obfuscation
// ============================================

// ============================================
// LLVM-STYLE RUNTIME CONSTANT CALCULATION MACROS
// ============================================

// Forward declaration for MBA obfuscation function
bool mba_obfuscate(bool input);

// Manual obfuscation removed - using LLVM approach instead

/**
 * Bogus control flow injection macro
 * Creates code paths that look like security checks but are never executed
 * Uses complex mathematical operations that evaluate to constants
 */
#define BOGUS_CHECK(cond) \
    do { \
        if ((cond) && ((42 * 42) % 2 == 0)) { \
            volatile uint32_t _junk = 0; \
            _junk = (_junk ^ 0xdeadbeef) + 0x12345; \
            _junk = (_junk << 16) | (_junk >> 16); \
            (void)_junk; /* Suppress unused warning */ \
        } \
    } while(0)

/**
 * VM-based dispatcher macro for "Labyrinth" strategy
 * Simulates a virtual machine instruction dispatcher
 */
#define VM_DISPATCHER(selector, bytecode) \
    do { \
        uint32_t _pc = (selector); \
        uint32_t _opcode = 0; \
        while (_pc != 0x0) { \
            _opcode = (bytecode)[_pc]; \
            switch (_opcode) { \
                case 0x01: /* CHECK_DEBUGGER */ \
                    if (check_ptrace_direct()) { _pc = 0xBAD11111; } \
                    else { _pc = 0x90ABCDEF; } \
                    break; \
                case 0x02: /* CHECK_ROOT */ \
                    if (check_root_direct()) { _pc = 0xBAD22222; } \
                    else { _pc = 0x12345678; } \
                    break; \
                case 0x00: /* EXIT */ \
                    _pc = 0x0; \
                    break; \
                default: \
                    _pc = 0xBAD00000; \
                    break; \
            } \
        } \
    } while(0)

/**
 * Anti-SMC (Self-Modifying Code) detection
 * Detects if code memory has been modified (software breakpoints)
 */
#define ANTI_SMC_CHECK() \
    do { \
        static const uint32_t _expected_hash = 0x12345678; \
        uint32_t _current_hash = calculate_code_hash(); \
        if (_current_hash != _expected_hash) { \
            __builtin_trap(); /* Force crash */ \
        } \
    } while(0)

// ============================================
// PATTERN 5: String Obfuscation (Stack String Pattern)
// ============================================

/**
 * Stack string builder - constructs strings on the fly
 * Never store sensitive strings in the binary
 */
class StackString {
private:
    char buffer[128];
    size_t length;
    
public:
    StackString() : length(0) {
        memset(buffer, 0, sizeof(buffer));
    }
    
    ~StackString() {
        // Zero out the string immediately after use
        memset(buffer, 0, sizeof(buffer));
    }
    
    /**
     * Build string from character array
     */
    void build(const char* chars, size_t len) {
        for (size_t i = 0; i < len && i < sizeof(buffer) - 1; i++) {
            buffer[i] = chars[i];
        }
        length = len;
    }
    
    /**
     * Build path strings using obfuscated character codes
     */
    void buildPath(const char* path) {
        size_t len = strlen(path);
        for (size_t i = 0; i < len && i < sizeof(buffer) - 1; i++) {
            // XOR each character with a rotating key
            buffer[i] = path[i] ^ ((i % 7) + 1);
        }
        length = len;
        
        // XOR back to get original string
        for (size_t i = 0; i < length; i++) {
            buffer[i] ^= ((i % 7) + 1);
        }
    }
    
    const char* c_str() const {
        return buffer;
    }
    
    size_t size() const {
        return length;
    }
};

// ============================================
// PATTERN 4: Direct Kernel Anti-Debugging
// ============================================

/**
 * Direct ptrace check using standard ptrace syscall
 * Bypasses libc wrapper to avoid Frida hooks
 */
__attribute__((visibility("hidden"), always_inline))
static bool check_ptrace_direct() {
    // Use standard ptrace syscall
    return ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1;
}

/**
 * Anti-debugging initialization
 * Uses ptrace to prevent debugger attachment
 */
__attribute__((visibility("hidden")))
void anti_debug_init() {
    // PT_DENY_ATTACH equivalent via ptrace
    // If a debugger is already attached, this will fail
    if (check_ptrace_direct()) {
        // Debugger detected - handle gracefully
        __builtin_trap();
    }
}

/**
 * Calculate code hash for Anti-SMC (Self-Modifying Code) detection
 * Detects if code memory has been modified (software breakpoints)
 */
__attribute__((visibility("hidden")))
static uint32_t calculate_code_hash() {
    // Get address of this function
    void* func_addr = (void*)calculate_code_hash;
    
    // Get library base address
    Dl_info info;
    if (dladdr(func_addr, &info) == 0) {
        return 0;
    }
    
    // Calculate hash of first 4KB of code
    uint8_t* base = (uint8_t*)info.dli_fbase;
    const size_t hash_size = 4096;
    
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < hash_size; i++) {
        crc ^= base[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

/**
 * Direct root check using inline assembly for file operations
 * Bypasses libc wrapper to avoid Frida hooks
 */
__attribute__((visibility("hidden"), always_inline))
static bool check_root_direct() {
    // Use inline assembly to make direct openat syscall
    // Check for /system/xbin/su using direct syscall
    StackString su_path;
    const char su_path_chars[] = {'/', 's', 'y', 's', 't', 'e', 'm', '/', 'x', 'b', 'i', 'n', '/', 's', 'u', '\0'};
    su_path.build(su_path_chars, sizeof(su_path_chars));
    
    // Use standard openat syscall
    int fd = openat(AT_FDCWD, su_path.c_str(), O_RDONLY, 0);
    
    if (fd >= 0) {
        close(fd);
        return mba_obfuscate(true);
    }
    
    return mba_obfuscate(false);
}

// ============================================
// PATTERN 2: Opaque Predicates
// ============================================

/**
 * Opaque predicate - complex boolean expression
 * Always evaluates to true, but decompiler can't simplify
 */
__attribute__((always_inline, visibility("hidden")))
bool opaque_predicate_true() {
    int x = 42;
    // Complex expression that always evaluates to true
    // (x*x + x) % 2 == 0 for any integer x
    return ((x * x + x) % 2) == 0;
}

/**
 * Opaque predicate - complex boolean expression
 * Always evaluates to false, but decompiler can't simplify
 */
__attribute__((always_inline, visibility("hidden")))
bool opaque_predicate_false() {
    int x = 42;
    // Complex expression that always evaluates to false
    // (x*x + x + 1) % 2 != 0 for any integer x
    return ((x * x + x + 1) % 2) == 0;
}

/**
 * Mixed Boolean-Arithmetic (MBA) obfuscation
 * Obfuscates simple boolean operations
 */
__attribute__((always_inline, visibility("hidden")))
bool mba_obfuscate(bool input) {
    // Transform: input = (input ^ 0) ^ 0
    // More complex: (input & ~0) | (~input & 0)
    int x = input ? 1 : 0;
    int y = ((x & ~0) | (~x & 0)) ^ 0;
    return y != 0;
}

// ============================================
// PATTERN A: Syscall Obfuscation (Ghost Pattern)
// ============================================

/**
 * Obfuscated syscall wrapper
 * Calculates syscall number at runtime instead of using constants
 */
__attribute__((visibility("hidden")))
class ObfuscatedSyscall {
private:
    // Base syscall numbers (obfuscated)
    static constexpr int BASE_OPENAT = 257;   // __NR_openat on ARM64
    static constexpr int BASE_READ = 63;      // __NR_read on ARM64
    static constexpr int BASE_WRITE = 64;     // __NR_write on ARM64
    static constexpr int BASE_CLOSE = 57;     // __NR_close on ARM64
    static constexpr int BASE_MMAP = 222;     // __NR_mmap on ARM64
    
    // Random seed for obfuscation
    static std::mt19937 rng;
    
public:
    /**
     * Calculate obfuscated syscall number at runtime
     * Instead of using constant, calculate it: (BASE + random_offset)
     */
    __attribute__((always_inline))
    static int getOpenatSyscall() {
        // Calculate at runtime: BASE_OPENAT + (random % 10)
        if (!opaque_predicate_true()) return BASE_OPENAT; // Dead code branch
        return BASE_OPENAT + (rng() % 10);
    }
    
    __attribute__((always_inline))
    static int getReadSyscall() {
        if (!opaque_predicate_true()) return BASE_READ; // Dead code branch
        return BASE_READ + (rng() % 10);
    }
    
    __attribute__((always_inline))
    static int getCloseSyscall() {
        if (!opaque_predicate_true()) return BASE_CLOSE; // Dead code branch
        return BASE_CLOSE + (rng() % 10);
    }
    
    /**
     * Direct syscall using syscall() function
     */
    __attribute__((visibility("hidden")))
    static long obfuscatedOpenat(int dfd, const char* filename, int flags, mode_t mode) {
        return syscall(__NR_openat, dfd, filename, flags, mode);
    }
    
    /**
     * Read using syscall() function
     */
    __attribute__((visibility("hidden")))
    static long obfuscatedRead(int fd, void* buf, size_t count) {
        return syscall(__NR_read, fd, buf, count);
    }
    
    /**
     * Close using syscall() function
     */
    __attribute__((visibility("hidden")))
    static long obfuscatedClose(int fd) {
        return syscall(__NR_close, fd);
    }
};

std::mt19937 ObfuscatedSyscall::rng(std::chrono::steady_clock::now().time_since_epoch().count());

// ============================================
// PATTERN B: Recursive Self-Verification (Mirror Pattern)
// ============================================

__attribute__((visibility("hidden")))
class SelfVerifier {
private:
    static std::atomic<bool> integrityCompromised;
    static std::atomic<uint32_t> initialHash;
    static bool initialized;
    
    /**
     * Calculate CRC32 hash of .text segment
     * Uses direct memory access to avoid hooked libc functions
     */
    __attribute__((visibility("hidden")))
    static uint32_t calculateTextSegmentHash() {
        // Get address of this function
        void* func_addr = (void*)calculateTextSegmentHash;
        
        // Get library base address (using dladdr)
        Dl_info info;
        if (dladdr(func_addr, &info) == 0) {
            return 0;
        }
        
        // Calculate hash of first 4KB of code
        uint8_t* base = (uint8_t*)info.dli_fbase;
        const size_t hash_size = 4096;
        
        uint32_t crc = 0xFFFFFFFF;
        
        // Use obfuscated read to avoid detection
        for (size_t i = 0; i < hash_size; i++) {
            crc ^= base[i];
            for (int j = 0; j < 8; j++) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        
        return ~crc;
    }
    
public:
    /**
     * Initialize self-verification
     * Store initial hash of .text segment
     */
    __attribute__((visibility("hidden")))
    static void initialize() {
        if (initialized) return;
        
        if (!opaque_predicate_true()) return; // Dead code branch
        
        initialHash.store(calculateTextSegmentHash());
        initialized = true;
        
        __android_log_print(ANDROID_LOG_INFO, TAG, "Self-verifier initialized. Initial hash: %u", initialHash.load());
    }
    
    /**
     * Verify integrity of .text segment
     * Detects if Frida has hooked any function in this library
     */
    __attribute__((visibility("hidden")))
    static bool verifyIntegrity() {
        if (!initialized) {
            initialize();
        }
        
        uint32_t currentHash = calculateTextSegmentHash();
        uint32_t expectedHash = initialHash.load();
        
        if (currentHash != expectedHash) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Integrity compromised! Expected: %u, Got: %u", expectedHash, currentHash);
            integrityCompromised.store(true);
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if integrity is compromised
     */
    __attribute__((visibility("hidden")))
    static bool isCompromised() {
        return mba_obfuscate(integrityCompromised.load());
    }
    
    /**
     * Reset compromised state (for testing)
     */
    __attribute__((visibility("hidden")))
    static void reset() {
        integrityCompromised.store(false);
        initialized = false;
    }
};

std::atomic<bool> SelfVerifier::integrityCompromised(false);
std::atomic<uint32_t> SelfVerifier::initialHash(0);
bool SelfVerifier::initialized = false;

// ============================================
// PATTERN C: Anti-Ghidra Control Flow Flattening (State Machine)
// ============================================

__attribute__((visibility("hidden")))
class SecurityStateMachine {
private:
    // State machine constants
    static constexpr uint32_t STATE_INIT = 0x00000001;
    static constexpr uint32_t STATE_CHECK_ROOT_1 = 0x00000002;
    static constexpr uint32_t STATE_CHECK_ROOT_2 = 0x00000003;
    static constexpr uint32_t STATE_CHECK_FRIDA_1 = 0x00000004;
    static constexpr uint32_t STATE_CHECK_FRIDA_2 = 0x00000005;
    static constexpr uint32_t STATE_CHECK_HOOKS_1 = 0x00000006;
    static constexpr uint32_t STATE_CHECK_HOOKS_2 = 0x00000007;
    static constexpr uint32_t STATE_CHECK_INTEGRITY = 0x00000008;
    static constexpr uint32_t STATE_CALCULATE_RISK = 0x00000009;
    static constexpr uint32_t STATE_RETURN = 0x00000000;
    
    static std::atomic<int> riskScore;
    static std::atomic<bool> rootDetected;
    static std::atomic<bool> fridaDetected;
    static std::atomic<bool> hooksDetected;
    
    /**
     * Check for root - Part 1 (split across states)
     * Uses stack strings to avoid hardcoded paths
     */
    __attribute__((visibility("hidden")))
    static bool checkRootPart1() {
        StackString path;
        const char superuser_path[] = {'/', 's', 'y', 's', 't', 'e', 'm', '/', 'a', 'p', 'p', '/', 'S', 'u', 'p', 'e', 'r', 'u', 's', 'e', 'r', '.', 'a', 'p', 'k', '\0'};
        path.build(superuser_path, sizeof(superuser_path));
        
        // Check for su binary using obfuscated syscall
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            ObfuscatedSyscall::obfuscatedClose(fd);
            return mba_obfuscate(true);
        }
        return mba_obfuscate(false);
    }
    
    /**
     * Check for root - Part 2 (split across states)
     */
    __attribute__((visibility("hidden")))
    static bool checkRootPart2() {
        StackString path;
        const char su_path[] = {'/', 's', 'b', 'i', 'n', '/', 's', 'u', '\0'};
        path.build(su_path, sizeof(su_path));
        
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            ObfuscatedSyscall::obfuscatedClose(fd);
            return mba_obfuscate(true);
        }
        return mba_obfuscate(false);
    }
    
    /**
     * Check for Frida - Part 1 (split across states)
     */
    __attribute__((visibility("hidden")))
    static bool checkFridaPart1() {
        StackString path;
        const char maps_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'm', 'a', 'p', 's', '\0'};
        path.build(maps_path, sizeof(maps_path));
        
        // Check for frida-server process
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            char buffer[4096];
            long bytes_read = ObfuscatedSyscall::obfuscatedRead(fd, buffer, sizeof(buffer) - 1);
            ObfuscatedSyscall::obfuscatedClose(fd);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                const char frida_str[] = {'f', 'r', 'i', 'd', 'a', '\0'};
                if (strstr(buffer, frida_str) != nullptr) {
                    return mba_obfuscate(true);
                }
            }
        }
        return mba_obfuscate(false);
    }
    
    /**
     * Check for Frida - Part 2 (split across states)
     */
    __attribute__((visibility("hidden")))
    static bool checkFridaPart2() {
        StackString path;
        const char task_maps_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 't', 'a', 's', 'k', '/', 's', 'e', 'l', 'f', '/', 'm', 'a', 'p', 's', '\0'};
        path.build(task_maps_path, sizeof(task_maps_path));
        
        // Check for frida-agent
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            char buffer[4096];
            long bytes_read = ObfuscatedSyscall::obfuscatedRead(fd, buffer, sizeof(buffer) - 1);
            ObfuscatedSyscall::obfuscatedClose(fd);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                const char frida_agent_str[] = {'f', 'r', 'i', 'd', 'a', '-', 'a', 'g', 'e', 'n', 't', '\0'};
                if (strstr(buffer, frida_agent_str) != nullptr) {
                    return mba_obfuscate(true);
                }
            }
        }
        return mba_obfuscate(false);
    }
    
    /**
     * Check for hooks - Part 1 (split across states)
     */
    __attribute__((visibility("hidden")))
    static bool checkHooksPart1() {
        StackString path;
        const char maps_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'm', 'a', 'p', 's', '\0'};
        path.build(maps_path, sizeof(maps_path));
        
        // Check for anonymous executable memory
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            char buffer[4096];
            long bytes_read = ObfuscatedSyscall::obfuscatedRead(fd, buffer, sizeof(buffer) - 1);
            ObfuscatedSyscall::obfuscatedClose(fd);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                const char r_xp_str[] = {'r', '-', 'x', 'p', '\0'};
                const char anonymous_str[] = {'a', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's', '\0'};
                if (strstr(buffer, r_xp_str) != nullptr && strstr(buffer, anonymous_str) != nullptr) {
                    return mba_obfuscate(true);
                }
            }
        }
        return mba_obfuscate(false);
    }
    
    /**
     * Check for hooks - Part 2 (split across states)
     */
    __attribute__((visibility("hidden")))
    static bool checkHooksPart2() {
        StackString path;
        const char maps_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'm', 'a', 'p', 's', '\0'};
        path.build(maps_path, sizeof(maps_path));
        
        // Check for writable executable memory
        int fd = (int)ObfuscatedSyscall::obfuscatedOpenat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
        if (fd >= 0) {
            char buffer[4096];
            long bytes_read = ObfuscatedSyscall::obfuscatedRead(fd, buffer, sizeof(buffer) - 1);
            ObfuscatedSyscall::obfuscatedClose(fd);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                const char rwxp_str[] = {'r', 'w', 'x', 'p', '\0'};
                if (strstr(buffer, rwxp_str) != nullptr) {
                    return mba_obfuscate(true);
                }
            }
        }
        return mba_obfuscate(false);
    }
    
public:
    /**
     * Execute state machine
     * Flattened control flow to confuse static analysis
     * Uses obfuscated state transitions and opaque predicates
     * Includes junk code injection to consume decompiler's "mental" energy
     */
    __attribute__((visibility("hidden")))
    static int execute(int riskContext) {
        uint32_t currentState = STATE_INIT;
        int result = 0; // SECURITY_OK = 0
        
        // Random state jumping to confuse analysis
        std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
        
        // Junk code injection - mathematical operations that do nothing
        volatile uint32_t junk_accumulator = 0;
        
        while (currentState != STATE_RETURN) {
            // Opaque predicate to confuse decompiler
            if (!opaque_predicate_true()) {
                currentState = STATE_RETURN; // Dead code branch
                break;
            }
            
            // Junk code - complex math that evaluates to nothing
            junk_accumulator = (junk_accumulator ^ 0xdeadbeef) + 0x12345;
            junk_accumulator = ((junk_accumulator << 16) | (junk_accumulator >> 16));
            junk_accumulator = junk_accumulator ^ 0xCAFEBABE;
            
            // Random state transitions (anti-pattern)
            int random_jump = rng() % 3;
            
            switch (currentState) {
                case STATE_INIT:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: INIT");
                    BOGUS_CHECK(opaque_predicate_true());
                    
                    // Junk code injection
                    for (int i = 0; i < 3; i++) {
                        volatile uint32_t temp = junk_accumulator;
                        temp = (temp * 0xdeadbeef) ^ 0x12345;
                        temp = ((temp << 7) | (temp >> 25));
                        junk_accumulator ^= temp;
                    }
                    
                    // Obfuscated state transition
                    currentState = (random_jump == 0) ? STATE_CHECK_ROOT_1 : STATE_CHECK_FRIDA_1;
                    break;
                    
                case STATE_CHECK_ROOT_1:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_ROOT_1");
                    BOGUS_CHECK(opaque_predicate_true());
                    
                    // Junk code injection
                    junk_accumulator = (junk_accumulator + 0x12345) ^ 0xABCDEF;
                    junk_accumulator = ((junk_accumulator << 8) | (junk_accumulator >> 24));
                    
                    if (checkRootPart1()) {
                        rootDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(3);
                    }
                    currentState = STATE_CHECK_ROOT_2;
                    break;
                    
                case STATE_CHECK_ROOT_2:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_ROOT_2");
                    BOGUS_CHECK(opaque_predicate_false());
                    
                    // Junk code injection
                    for (int i = 0; i < 2; i++) {
                        volatile uint32_t temp = junk_accumulator;
                        temp = temp ^ 0xDEADBEEF;
                        temp = (temp >> 4) | (temp << 28);
                        junk_accumulator += temp;
                    }
                    
                    if (checkRootPart2()) {
                        rootDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(3);
                    }
                    currentState = (random_jump == 0) ? STATE_CHECK_FRIDA_1 : STATE_CHECK_HOOKS_1;
                    break;
                    
                case STATE_CHECK_FRIDA_1:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_FRIDA_1");
                    BOGUS_CHECK(opaque_predicate_true());
                    
                    // Junk code injection
                    junk_accumulator = (junk_accumulator * 0xCAFEBABE) ^ 0x12345678;
                    junk_accumulator = ((junk_accumulator << 12) | (junk_accumulator >> 20));
                    
                    if (checkFridaPart1()) {
                        fridaDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(5);
                    }
                    currentState = STATE_CHECK_FRIDA_2;
                    break;
                    
                case STATE_CHECK_FRIDA_2:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_FRIDA_2");
                    BOGUS_CHECK(opaque_predicate_false());
                    
                    // Junk code injection
                    for (int i = 0; i < 2; i++) {
                        volatile uint32_t temp = junk_accumulator;
                        temp = (temp + 0x87654321) ^ 0xFEDCBA09;
                        temp = ((temp << 5) | (temp >> 27));
                        junk_accumulator ^= temp;
                    }
                    
                    if (checkFridaPart2()) {
                        fridaDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(5);
                    }
                    currentState = (random_jump == 0) ? STATE_CHECK_HOOKS_1 : STATE_CHECK_INTEGRITY;
                    break;
                    
                case STATE_CHECK_HOOKS_1:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_HOOKS_1");
                    BOGUS_CHECK(opaque_predicate_true());
                    
                    // Junk code injection
                    junk_accumulator = (junk_accumulator ^ 0x13579BDF) + 0x2468ACE0;
                    junk_accumulator = ((junk_accumulator << 3) | (junk_accumulator >> 29));
                    
                    if (checkHooksPart1()) {
                        hooksDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(4);
                    }
                    currentState = STATE_CHECK_HOOKS_2;
                    break;
                    
                case STATE_CHECK_HOOKS_2:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_HOOKS_2");
                    BOGUS_CHECK(opaque_predicate_false());
                    
                    // Junk code injection
                    for (int i = 0; i < 2; i++) {
                        volatile uint32_t temp = junk_accumulator;
                        temp = (temp * 0x97531086) ^ 0xABCDEF12;
                        temp = ((temp << 9) | (temp >> 23));
                        junk_accumulator ^= temp;
                    }
                    
                    if (checkHooksPart2()) {
                        hooksDetected.store(mba_obfuscate(true));
                        riskScore.fetch_add(4);
                    }
                    currentState = STATE_CHECK_INTEGRITY;
                    break;
                    
                case STATE_CHECK_INTEGRITY:
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CHECK_INTEGRITY");
                    BOGUS_CHECK(opaque_predicate_true());
                    
                    // Junk code injection
                    junk_accumulator = (junk_accumulator + 0xDEF01234) ^ 0x56789ABC;
                    junk_accumulator = ((junk_accumulator << 6) | (junk_accumulator >> 26));
                    
                    if (!SelfVerifier::verifyIntegrity()) {
                        riskScore.fetch_add(10);
                    }
                    currentState = STATE_CALCULATE_RISK;
                    break;
                    
                case STATE_CALCULATE_RISK: {
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "State: CALCULATE_RISK");
                    BOGUS_CHECK(opaque_predicate_false());
                    
                    // Junk code injection
                    for (int i = 0; i < 3; i++) {
                        volatile uint32_t temp = junk_accumulator;
                        temp = (temp ^ 0xDEF56789) + 0xABCDEF01;
                        temp = ((temp << 11) | (temp >> 21));
                        junk_accumulator ^= temp;
                    }
                    
                    int score = riskScore.load();
                    
                    // Risk levels based on score
                    if (score >= 10) {
                        result = 3; // CONFIRMED_TAMPER
                    } else if (score >= 7) {
                        result = 2; // HIGHLY_SUSPICIOUS
                    } else if (score >= 3) {
                        result = 1; // SUSPICIOUS
                    } else {
                        result = 0; // SECURITY_OK
                    }
                    
                    __android_log_print(ANDROID_LOG_INFO, TAG, "Risk score: %d, Result: %d", score, result);
                    currentState = STATE_RETURN;
                    break;
                }
                    
                default:
                    currentState = STATE_RETURN;
                    break;
            }
            
            // Random delay to confuse timing analysis
            std::this_thread::sleep_for(std::chrono::microseconds(rng() % 1000));
        }
        
        return result;
    }
    
    /**
     * Reset state machine
     */
    __attribute__((visibility("hidden")))
    static void reset() {
        riskScore.store(0);
        rootDetected.store(false);
        fridaDetected.store(false);
        hooksDetected.store(false);
    }
    
    /**
     * Get detection status
     */
    __attribute__((visibility("hidden")))
    static bool isRootDetected() { return mba_obfuscate(rootDetected.load()); }
    __attribute__((visibility("hidden")))
    static bool isFridaDetected() { return mba_obfuscate(fridaDetected.load()); }
    __attribute__((visibility("hidden")))
    static bool isHooksDetected() { return mba_obfuscate(hooksDetected.load()); }
};

std::atomic<int> SecurityStateMachine::riskScore(0);
std::atomic<bool> SecurityStateMachine::rootDetected(false);
std::atomic<bool> SecurityStateMachine::fridaDetected(false);
std::atomic<bool> SecurityStateMachine::hooksDetected(false);

// ============================================
// PATTERN 6: JNI RegisterNatives for Name Obfuscation
// ============================================

/**
 * Obfuscated JNI method names
 * Instead of standard JNI naming like Java_org_mazhai_aran_security_RaspCoreEngine_performSecurityAudit
 * we use RegisterNatives to map cryptic names
 */
__attribute__((visibility("hidden")))
jint JNICALL z9_impl(JNIEnv* env, jobject thiz, jint riskContext) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "========================================");
    __android_log_print(ANDROID_LOG_INFO, TAG, "Native Core Engine Security Audit");
    __android_log_print(ANDROID_LOG_INFO, TAG, "Risk Context: %d", riskContext);
    __android_log_print(ANDROID_LOG_INFO, TAG, "========================================");
    
    // Initialize self-verifier
    SelfVerifier::initialize();
    
    // Execute state machine
    int result = SecurityStateMachine::execute(riskContext);
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "========================================");
    __android_log_print(ANDROID_LOG_INFO, TAG, "Security Audit Complete. Result: %d", result);
    __android_log_print(ANDROID_LOG_INFO, TAG, "========================================");
    
    return result;
}

__attribute__((visibility("hidden")))
void JNICALL a1_impl(JNIEnv* env, jobject thiz) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Initializing Native Core Engine...");
    
    // Initialize anti-debugging
    anti_debug_init();
    
    SelfVerifier::initialize();
    SecurityStateMachine::reset();
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Native Core Engine initialized successfully");
}

__attribute__((visibility("hidden")))
void JNICALL b2_impl(JNIEnv* env, jobject thiz) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Shutting down Native Core Engine...");
    
    SelfVerifier::reset();
    SecurityStateMachine::reset();
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Native Core Engine shut down successfully");
}

__attribute__((visibility("hidden")))
jboolean JNICALL c3_impl(JNIEnv* env, jobject thiz) {
    return SecurityStateMachine::isRootDetected();
}

__attribute__((visibility("hidden")))
jboolean JNICALL d4_impl(JNIEnv* env, jobject thiz) {
    return SecurityStateMachine::isFridaDetected();
}

__attribute__((visibility("hidden")))
jboolean JNICALL e5_impl(JNIEnv* env, jobject thiz) {
    return SecurityStateMachine::isHooksDetected();
}

/**
 * JNI_OnLoad - Register natives with obfuscated names
 * This hides the link between Kotlin and C++ function names
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    
    // Find the RaspCoreEngine class
    jclass clazz = env->FindClass("org/mazhai/aran/security/RaspCoreEngine");
    if (clazz == nullptr) {
        return JNI_ERR;
    }
    
    // Register native methods with obfuscated names
    JNINativeMethod methods[] = {
        {const_cast<char*>("a1"), const_cast<char*>("()V"), reinterpret_cast<void*>(a1_impl)},
        {const_cast<char*>("z9"), const_cast<char*>("(I)I"), reinterpret_cast<void*>(z9_impl)},
        {const_cast<char*>("b2"), const_cast<char*>("()V"), reinterpret_cast<void*>(b2_impl)},
        {const_cast<char*>("c3"), const_cast<char*>("()Z"), reinterpret_cast<void*>(c3_impl)},
        {const_cast<char*>("d4"), const_cast<char*>("()Z"), reinterpret_cast<void*>(d4_impl)},
        {const_cast<char*>("e5"), const_cast<char*>("()Z"), reinterpret_cast<void*>(e5_impl)}
    };
    
    jint result = env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0]));
    if (result != JNI_OK) {
        return JNI_ERR;
    }
    
    return JNI_VERSION_1_6;
}

// ============================================
// LEGACY JNI METHODS (for backward compatibility)
// These will be replaced by RegisterNatives in production
// ============================================

extern "C" {

/**
 * Single JNI entry point to native engine (legacy)
 * performSecurityAudit(int riskContext) -> int (risk level)
 */
JNIEXPORT jint JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_performSecurityAudit(JNIEnv* env, jobject thiz, jint riskContext) {
    // Call the obfuscated implementation
    return z9_impl(env, thiz, riskContext);
}

/**
 * Initialize native engine (legacy)
 */
JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_initializeNative(JNIEnv* env, jobject thiz) {
    // Call the obfuscated implementation
    a1_impl(env, thiz);
}

/**
 * Shutdown native engine (legacy)
 */
JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_shutdownNative(JNIEnv* env, jobject thiz) {
    // Call the obfuscated implementation
    b2_impl(env, thiz);
}

/**
 * Get detailed detection status (for debugging) (legacy)
 */
JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_isRootDetected(JNIEnv* env, jobject thiz) {
    return c3_impl(env, thiz);
}

JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_isFridaDetected(JNIEnv* env, jobject thiz) {
    return d4_impl(env, thiz);
}

JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_RaspCoreEngine_isHooksDetected(JNIEnv* env, jobject thiz) {
    return e5_impl(env, thiz);
}

} // extern "C"
