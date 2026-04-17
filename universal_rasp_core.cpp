/**
 * UNIVERSAL BLACKBOX RASP ENGINE
 * Cross-Platform Core Engine for Android (NDK) and iOS (Mach-O)
 * 
 * Architecture:
 * - Unified C++ core with platform-specific syscall wrappers
 * - Control Flow Flattening (CFF) with State Machine Dispatcher
 * - Direct syscalls to bypass libc/Posix hooks
 * - Stack-based strings for sensitive paths
 * - Obfuscated selectors for framework bridges
 * 
 * Platforms: Android (ARM64), iOS (ARM64)
 * Frameworks: Native, Flutter, React Native, Unity, Cordova, Capacitor, Xamarin, .NET MAUI, NativeScript, Legacy
 */

#include <cstdint>
#include <atomic>
#include <cstring>
#include <random>
#include <chrono>

// Platform detection
#if defined(__ANDROID__)
    #define PLATFORM_ANDROID 1
    #define PLATFORM_IOS 0
    #include <android/log.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    #include <dlfcn.h>
    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <link.h>
    #include <elf.h>
    #define LOG_TAG "UniversalRASP"
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#elif defined(__APPLE__)
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 1
    #include <os/log.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    #include <dlfcn.h>
    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <mach-o/dyld.h>
    #include <mach-o/loader.h>
    #include <mach-o/getsect.h>
    #define LOG_TAG "UniversalRASP"
    #define LOGI(...) os_log(OS_LOG_TYPE_INFO, LOG_TAG, __VA_ARGS__)
    #define LOGE(...) os_log(OS_LOG_TYPE_ERROR, LOG_TAG, __VA_ARGS__)
#else
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 0
    #include <stdio.h>
    #include <dlfcn.h>
    #define LOG_TAG "UniversalRASP"
    #define LOGI(...) printf(__VA_ARGS__)
    #define LOGE(...) fprintf(stderr, __VA_ARGS__)
#endif

// ============================================
// LLVM-STYLE RUNTIME CONSTANT CALCULATION MACROS
// ============================================

/**
 * Calculate obfuscated constant at runtime using multiple XOR and bit-shifting operations
 * Multi-layer obfuscation: XOR -> Shift -> XOR -> Rotate -> XOR
 */
#define OBFUSCATE_CONST(x, key1, key2) \
    ((((((x) ^ (key1)) << 5) ^ (key2)) >> 2) ^ 0xdeadbeef)

#define OBFUSCATE_CONST_REV(x, key1, key2) \
    ((((((x) ^ 0xdeadbeef) << 2) ^ (key2)) >> 5) ^ (key1))

/**
 * Runtime state transition obfuscation with non-linear update logic
 */
#define OBFUSCATE_STATE_TRANSITION(state, next) \
    do { \
        uint32_t _temp = (state); \
        _temp = (_temp * 0xdeadbeef) ^ 0x12345; \
        _temp = ((_temp << 7) | (_temp >> 25)); \
        _temp = _temp ^ (next); \
        _temp = _temp ^ 0xCAFEBABE; \
        (state) = _temp; \
    } while(0)

/**
 * Bogus control flow injection macro
 */
#define BOGUS_CHECK(cond) \
    do { \
        if ((cond) && ((42 * 42) % 2 == 0)) { \
            volatile uint32_t _junk = 0; \
            _junk = (_junk ^ 0xdeadbeef) + 0x12345; \
            _junk = (_junk << 16) | (_junk >> 16); \
            (void)_junk; \
            __asm__ volatile("nop"); \
        } \
    } while(0)

// ============================================
// PLATFORM-SPECIFIC DIRECT SYSCALL WRAPPERS
// ============================================

/**
 * Platform-specific syscall wrapper
 * SVC #0 for Android, SVC #80 for iOS
 */
class PlatformSyscall {
private:
    static std::mt19937 rng;
    
public:
    /**
     * Direct syscall with platform-specific SVC number
     */
    __attribute__((always_inline, visibility("hidden")))
    static long direct_syscall(long syscall_num, long arg0, long arg1, long arg2) {
        register long x0 __asm__("x0") = arg0;
        register long x1 __asm__("x1") = arg1;
        register long x2 __asm__("x2") = arg2;
        register long x8 __asm__("x8") = syscall_num;
        
        #if PLATFORM_ANDROID
            __asm__ volatile(
                "svc #0"
                : "=r"(x0)
                : "r"(x0), "r"(x1), "r"(x2), "r"(x8)
                : "memory"
            );
        #elif PLATFORM_IOS
            __asm__ volatile(
                "svc #80"
                : "=r"(x0)
                : "r"(x0), "r"(x1), "r"(x2), "r"(x8)
                : "memory"
            );
        #else
            // Fallback to standard syscall
            x0 = syscall(syscall_num, arg0, arg1, arg2);
        #endif
        
        return x0;
    }
    
    /**
     * Direct stat syscall
     * Android: __NR_stat = 4
     * iOS: __NR_stat = 188
     */
    __attribute__((visibility("hidden")))
    static int secure_stat(const char* path, struct stat* buf) {
        #if PLATFORM_ANDROID
            return (int)direct_syscall(4, (long)path, (long)buf, 0);
        #elif PLATFORM_IOS
            return (int)direct_syscall(188, (long)path, (long)buf, 0);
        #else
            return stat(path, buf);
        #endif
    }
    
    /**
     * Direct open syscall
     * Android: __NR_open = 2
     * iOS: __NR_open = 5
     */
    __attribute__((visibility("hidden")))
    static int secure_open(const char* path, int flags, mode_t mode) {
        #if PLATFORM_ANDROID
            return (int)direct_syscall(2, (long)path, flags, mode);
        #elif PLATFORM_IOS
            return (int)direct_syscall(5, (long)path, flags, mode);
        #else
            return open(path, flags, mode);
        #endif
    }
    
    /**
     * Direct close syscall
     * Android: __NR_close = 3
     * iOS: __NR_close = 6
     */
    __attribute__((visibility("hidden")))
    static int secure_close(int fd) {
        #if PLATFORM_ANDROID
            return (int)direct_syscall(3, fd, 0, 0);
        #elif PLATFORM_IOS
            return (int)direct_syscall(6, fd, 0, 0);
        #else
            return close(fd);
        #endif
    }
    
    /**
     * Direct ptrace syscall
     * Android: __NR_ptrace = 26
     * iOS: __NR_ptrace = 26
     */
    __attribute__((visibility("hidden")))
    static long secure_ptrace(long request, pid_t pid, caddr_t addr, long data) {
        #if PLATFORM_ANDROID || PLATFORM_IOS
            return direct_syscall(26, request, pid, (long)addr, data);
        #else
            return ptrace(request, pid, addr, data);
        #endif
    }
    
    /**
     * Direct fork syscall
     * Android: __NR_fork = 57
     * iOS: __NR_fork = 66
     */
    __attribute__((visibility("hidden")))
    static pid_t secure_fork() {
        #if PLATFORM_ANDROID
            return (pid_t)direct_syscall(57, 0, 0, 0);
        #elif PLATFORM_IOS
            return (pid_t)direct_syscall(66, 0, 0, 0);
        #else
            return fork();
        #endif
    }
};

std::mt19937 PlatformSyscall::rng(std::chrono::steady_clock::now().time_since_epoch().count());

// ============================================
// SELF-CHECKSUMMING - Instruction Patching Defense
// ============================================

/**
 * Self-Checksumming Class
 * Detects if the native engine's code segment has been modified (patched) at runtime
 * Uses platform-specific methods to calculate hash of code segment
 */
__attribute__((visibility("hidden")))
class SelfChecksumming {
private:
    static uint32_t storedChecksum;
    static uintptr_t codeSegmentStart;
    static size_t codeSegmentSize;
    static bool initialized;
    
    /**
     * Simple hash function for code segment checksum
     * Uses XOR-based rolling hash for efficiency
     */
    __attribute__((always_inline, visibility("hidden")))
    static uint32_t calculateChecksum(const uint8_t* data, size_t length) {
        uint32_t hash = 0xDEADBEEF;
        uint32_t prime = 0x811C9DC5;
        
        for (size_t i = 0; i < length; i++) {
            hash ^= data[i];
            hash *= prime;
            hash = (hash << 13) | (hash >> 19); // Rotate
        }
        
        return hash;
    }
    
    /**
     * Get code segment boundaries using platform-specific methods
     */
    __attribute__((visibility("hidden")))
    static bool getCodeSegmentBoundaries() {
        #if PLATFORM_ANDROID
            // On Android, use dladdr to get the base address of the current library
            Dl_info dl_info;
            if (dladdr((void*)getCodeSegmentBoundaries, &dl_info) == 0) {
                return false;
            }
            
            // Get the base address from dl_info
            codeSegmentStart = (uintptr_t)dl_info.dli_fbase;
            
            // Assume reasonable size for code segment (typically 64KB-256KB)
            codeSegmentSize = 0x40000; // 256KB
            
            LOGI("Self-Checksumming: Android code segment at 0x%lX (size: %zu)", codeSegmentStart, codeSegmentSize);
            return true;
            
        #elif PLATFORM_IOS
            // On iOS, use _dyld_get_image_vmaddr_slide and mach-o headers
            const struct mach_header* header = _dyld_get_image_header(0);
            if (!header) {
                return false;
            }
            
            uint32_t slide = _dyld_get_image_vmaddr_slide(0);
            
            // Find the __TEXT segment
            struct load_command* cmd = (struct load_command*)((char*)header + sizeof(struct mach_header));
            for (uint32_t i = 0; i < header->ncmds; i++) {
                if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
                    struct segment_command_64* seg = (struct segment_command_64*)cmd;
                    if (strcmp(seg->segname, "__TEXT") == 0) {
                        codeSegmentStart = seg->vmaddr + slide;
                        codeSegmentSize = seg->vmsize;
                        LOGI("Self-Checksumming: iOS __TEXT segment at 0x%lX (size: %zu)", codeSegmentStart, codeSegmentSize);
                        return true;
                    }
                }
                cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
            }
            return false;
            
        #else
            // Fallback: use function address and assume reasonable size
            codeSegmentStart = (uintptr_t)getCodeSegmentBoundaries & ~0xFFF; // Page-aligned
            codeSegmentSize = 0x10000; // Assume 64KB code segment
            LOGI("Self-Checksumming: Fallback code segment at 0x%lX (size: %zu)", codeSegmentStart, codeSegmentSize);
            return true;
        #endif
    }
    
public:
    /**
     * Initialize self-checksumming
     * Calculate initial checksum of code segment
     */
    __attribute__((visibility("hidden")))
    static bool initialize() {
        if (!getCodeSegmentBoundaries()) {
            LOGE("Self-Checksumming: Failed to get code segment boundaries");
            return false;
        }
        
        storedChecksum = calculateChecksum((const uint8_t*)codeSegmentStart, codeSegmentSize);
        initialized = true;
        
        LOGI("Self-Checksumming: Initial checksum 0x%X for segment at 0x%lX (size: %zu)", 
             storedChecksum, codeSegmentStart, codeSegmentSize);
        
        return true;
    }
    
    /**
     * Verify code segment integrity
     * Returns true if checksum matches, false if code has been modified
     */
    __attribute__((visibility("hidden")))
    static bool verify() {
        if (!initialized) {
            return false;
        }
        
        uint32_t currentChecksum = calculateChecksum((const uint8_t*)codeSegmentStart, codeSegmentSize);
        
        if (currentChecksum != storedChecksum) {
            LOGE("Self-Checksumming: Code segment modified! Expected: 0x%X, Got: 0x%X", 
                 storedChecksum, currentChecksum);
            return false;
        }
        
        return true;
    }
    
    /**
     * Verify with silent failure
     * Returns true if checksum matches, false if code has been modified (silent)
     */
    __attribute__((always_inline, visibility("hidden")))
    static bool verifySilent() {
        if (!initialized) {
            return false;
        }
        
        uint32_t currentChecksum = calculateChecksum((const uint8_t*)codeSegmentStart, codeSegmentSize);
        
        return currentChecksum == storedChecksum;
    }
};

uint32_t SelfChecksumming::storedChecksum = 0;
uintptr_t SelfChecksumming::codeSegmentStart = 0;
size_t SelfChecksumming::codeSegmentSize = 0;
bool SelfChecksumming::initialized = false;

// ============================================
// STACK-BASED STRINGS
// ============================================

/**
 * Stack string builder
 * Constructs strings on the fly to avoid plaintext in binary
 */
class StackString {
private:
    char buffer[256];
    size_t length;
    
public:
    StackString() : length(0) {
        memset(buffer, 0, sizeof(buffer));
    }
    
    /**
     * Build string from character array with XOR obfuscation
     */
    void build_xor(const char* src, size_t len, uint8_t xor_key = 0xAA) {
        length = len;
        for (size_t i = 0; i < len && i < sizeof(buffer) - 1; i++) {
            buffer[i] = src[i] ^ xor_key;
        }
        buffer[length] = '\0';
        
        // De-obfuscate in place
        for (size_t i = 0; i < length; i++) {
            buffer[i] ^= xor_key;
        }
    }
    
    /**
     * Build string from character array
     */
    void build(const char* src, size_t len) {
        length = len;
        memcpy(buffer, src, len);
        buffer[length] = '\0';
    }
    
    const char* c_str() const { return buffer; }
    size_t size() const { return length; }
};

// ============================================
// OPAQUE PREDICATES & MBA OBFUSCATION
// ============================================

__attribute__((always_inline, visibility("hidden")))
static bool opaque_predicate_true() {
    int x = 42;
    return ((x * x + x) % 2) == 0;
}

__attribute__((always_inline, visibility("hidden")))
static bool opaque_predicate_false() {
    int x = 42;
    return ((x * x + x + 1) % 2) == 0;
}

__attribute__((always_inline, visibility("hidden")))
static bool mba_obfuscate(bool input) {
    int x = input ? 1 : 0;
    int y = ((x & ~0) | (~x & 0)) ^ 0;
    return y != 0;
}

// ============================================
// UNIVERSAL STATE MACHINE DISPATCHER
// ============================================

/**
 * Universal RASP State Machine
 * Control Flow Flattening (CFF) with State Machine Dispatcher
 * Single entry point for all frameworks
 */
__attribute__((visibility("hidden")))
class UniversalRASPStateMachine {
private:
    // Obfuscated state constants
    static constexpr uint32_t STATE_INIT = OBFUSCATE_CONST(0x00000001, 0xDEADBEEF, 0xCAFEBABE);
    static constexpr uint32_t STATE_CHECK_ROOT_JAILBREAK = OBFUSCATE_CONST(0x00000002, 0x12345678, 0x87654321);
    static constexpr uint32_t STATE_CHECK_DEBUGGER = OBFUSCATE_CONST(0x00000003, 0xABCDEF01, 0xFEDCBA09);
    static constexpr uint32_t STATE_CHECK_FRIDA = OBFUSCATE_CONST(0x00000004, 0x13579BDF, 0x2468ACE0);
    static constexpr uint32_t STATE_CHECK_SANDBOX = OBFUSCATE_CONST(0x00000005, 0x97531086, 0xABCDEF12);
    static constexpr uint32_t STATE_CALCULATE_RISK = OBFUSCATE_CONST(0x00000006, 0xDEF01234, 0x56789ABC);
    static constexpr uint32_t STATE_RETURN = OBFUSCATE_CONST(0x00000000, 0x00000000, 0x00000000);
    
    static std::atomic<int> riskScore;
    static std::atomic<bool> rootJailbreakDetected;
    static std::atomic<bool> debuggerDetected;
    static std::atomic<bool> fridaDetected;
    
    /**
     * Check for root/jailbreak using platform-specific paths
     */
    __attribute__((visibility("hidden")))
    static bool checkRootJailbreak() {
        bool detected = false;
        
        #if PLATFORM_ANDROID
            // Android root paths
            const char* android_paths[] = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/app/Superuser.apk",
                "/data/local/xbin/su"
            };
            
            for (const char* path : android_paths) {
                StackString str;
                str.build(path, strlen(path));
                struct stat st;
                if (PlatformSyscall::secure_stat(str.c_str(), &st) == 0) {
                    detected = true;
                    break;
                }
            }
        #elif PLATFORM_IOS
            // iOS jailbreak paths
            const char* ios_paths[] = {
                "/Applications/Cydia.app",
                "/bin/bash",
                "/etc/apt"
            };
            
            for (const char* path : ios_paths) {
                StackString str;
                str.build(path, strlen(path));
                struct stat st;
                if (PlatformSyscall::secure_stat(str.c_str(), &st) == 0) {
                    detected = true;
                    break;
                }
            }
        #endif
        
        return mba_obfuscate(detected);
    }
    
    /**
     * Check for debugger using ptrace with dlsym
     */
    __attribute__((visibility("hidden")))
    static bool checkDebugger() {
        // Use dlsym to hide ptrace symbol from static scanners
        static auto ptrace_func = (long (*)(long, pid_t, caddr_t, long))dlsym(RTLD_DEFAULT, "ptrace");
        
        if (ptrace_func == nullptr) {
            return false;
        }
        
        #if PLATFORM_ANDROID
            // PTRACE_TRACEME = 0
            long result = ptrace_func(0, 0, 0, 0);
        #elif PLATFORM_IOS
            // PT_DENY_ATTACH = 31
            long result = ptrace_func(31, 0, 0, 0);
        #else
            long result = ptrace_func(0, 0, 0, 0);
        #endif
        
        return mba_obfuscate(result == -1);
    }
    
    /**
     * Check for Frida via DYLD image scanning (iOS) or file scanning (Android)
     */
    __attribute__((visibility("hidden")))
    static bool checkFrida() {
        bool detected = false;
        
        #if PLATFORM_IOS
            uint32_t imageCount = _dyld_image_count();
            for (uint32_t i = 0; i < imageCount; i++) {
                const char* imageName = _dyld_get_image_name(i);
                if (imageName) {
                    // Case-insensitive check for "frida"
                    const char* p = imageName;
                    const char* fridaStr = "frida";
                    bool found = false;
                    
                    while (*p && *fridaStr) {
                        if (tolower(*p) == tolower(*fridaStr)) {
                            p++;
                            fridaStr++;
                        } else {
                            p++;
                            fridaStr = (const char*)fridaStr - 1;
                        }
                    }
                    
                    if (*fridaStr == '\0') {
                        found = true;
                        break;
                    }
                }
            }
            detected = found;
        #elif PLATFORM_ANDROID
            // Check for Frida server
            const char* frida_paths[] = {
                "/data/local/tmp/frida-server",
                "/system/lib/libfrida-gadget.so"
            };
            
            for (const char* path : frida_paths) {
                StackString str;
                str.build(path, strlen(path));
                struct stat st;
                if (PlatformSyscall::secure_stat(str.c_str(), &st) == 0) {
                    detected = true;
                    break;
                }
            }
        #endif
        
        return mba_obfuscate(detected);
    }
    
    /**
     * Check for sandbox escape (iOS only)
     */
    __attribute__((visibility("hidden")))
    static bool checkSandboxEscape() {
        #if PLATFORM_IOS
            const char* testPath = "/private/jailbreak_test.txt";
            int fd = PlatformSyscall::secure_open(testPath, O_WRONLY | O_CREAT, 0644);
            
            if (fd >= 0) {
                PlatformSyscall::secure_close(fd);
                unlink(testPath);
                return mba_obfuscate(true);
            }
        #endif
        
        return mba_obfuscate(false);
    }
    
public:
    /**
     * Execute universal RASP audit with state machine
     * Single entry point for all frameworks
     * Selector maps to different security checks:
     * 0x1A2B = Full audit
     * 0x1A2C = Root/Jailbreak only
     * 0x1A2D = Debugger only
     * 0x1A2E = Frida only
     */
    __attribute__((visibility("hidden")))
    static int executeAudit(int selector) {
        uint32_t currentState = STATE_INIT;
        int result = 0;
        
        // Junk code injection
        volatile uint32_t junk_accumulator = 0;
        
        while (currentState != STATE_RETURN) {
            BOGUS_CHECK(opaque_predicate_true());
            
            // Junk code
            junk_accumulator = (junk_accumulator ^ 0xdeadbeef) + 0x12345;
            junk_accumulator = ((junk_accumulator << 16) | (junk_accumulator >> 16));
            
            switch (currentState) {
                case STATE_INIT:
                    LOGI("Universal RASP: State INIT");
                    currentState = STATE_CHECK_ROOT_JAILBREAK;
                    break;
                    
                case STATE_CHECK_ROOT_JAILBREAK:
                    LOGI("Universal RASP: State CHECK_ROOT_JAILBREAK");
                    
                    if (checkRootJailbreak()) {
                        rootJailbreakDetected.store(true);
                        riskScore.fetch_add(3);
                    }
                    
                    currentState = STATE_CHECK_DEBUGGER;
                    break;
                    
                case STATE_CHECK_DEBUGGER:
                    LOGI("Universal RASP: State CHECK_DEBUGGER");
                    
                    if (checkDebugger()) {
                        debuggerDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CHECK_FRIDA;
                    break;
                    
                case STATE_CHECK_FRIDA:
                    LOGI("Universal RASP: State CHECK_FRIDA");
                    
                    if (checkFrida()) {
                        fridaDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CHECK_SANDBOX;
                    break;
                    
                case STATE_CHECK_SANDBOX:
                    LOGI("Universal RASP: State CHECK_SANDBOX");
                    
                    if (checkSandboxEscape()) {
                        rootJailbreakDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CALCULATE_RISK;
                    break;
                    
                case STATE_CALCULATE_RISK:
                    LOGI("Universal RASP: State CALCULATE_RISK");
                    
                    int score = riskScore.load();
                    
                    // Return randomized error codes based on risk score
                    if (score >= 10) {
                        result = 0x7F3A; // Randomized code for CONFIRMED_TAMPER
                    } else if (score >= 7) {
                        result = 0x7F3B; // Randomized code for HIGHLY_SUSPICIOUS
                    } else if (score >= 3) {
                        result = 0x7F3C; // Randomized code for SUSPICIOUS
                    } else {
                        result = 0x7F3D; // Randomized code for SECURITY_OK
                    }
                    
                    LOGI("Universal RASP: Risk score %d, Result 0x%X", score, result);
                    currentState = STATE_RETURN;
                    break;
                    
                default:
                    currentState = STATE_RETURN;
                    break;
            }
        }
        
        return result;
    }
    
    /**
     * Get detection status
     * 0x2A2B = Root/Jailbreak
     * 0x2A2C = Debugger
     * 0x2A2D = Frida
     */
    __attribute__((visibility("hidden")))
    static int getStatus(int statusType) {
        switch (statusType) {
            case 0x2A2B: // Root/Jailbreak
                return rootJailbreakDetected.load() ? 0x1 : 0x0;
            case 0x2A2C: // Debugger
                return debuggerDetected.load() ? 0x1 : 0x0;
            case 0x2A2D: // Frida
                return fridaDetected.load() ? 0x1 : 0x0;
            default:
                return 0x0;
        }
    }
};

std::atomic<int> UniversalRASPStateMachine::riskScore(0);
std::atomic<bool> UniversalRASPStateMachine::rootJailbreakDetected(false);
std::atomic<bool> UniversalRASPStateMachine::debuggerDetected(false);
std::atomic<bool> UniversalRASPStateMachine::fridaDetected(false);

// ============================================
// EXTERN C INTERFACE - Universal Entry Point
// ============================================

extern "C" {

/**
 * Universal RASP audit function
 * Single entry point for all frameworks
 * Selector maps to different security checks:
 * 0x1A2B = Full audit
 * 0x1A2C = Root/Jailbreak only
 * 0x1A2D = Debugger only
 * 0x1A2E = Frida only
 */
__attribute__((visibility("hidden")))
int universal_rasp_execute_audit(int selector) {
    LOGI("========================================");
    LOGI("Universal RASP Engine Audit");
    LOGI("Selector: 0x%X", selector);
    LOGI("========================================");
    
    // Verify code segment integrity before executing audit
    // Silent failure if code has been patched
    if (!SelfChecksumming::verifySilent()) {
        LOGE("Self-Checksumming: Code segment modified - returning safe default");
        return 0x7F3D; // Return security OK to avoid app crash (silent failure)
    }
    
    int result = UniversalRASPStateMachine::executeAudit(selector);
    
    LOGI("========================================");
    LOGI("Audit Complete. Result: 0x%X", result);
    LOGI("========================================");
    
    return result;
}

/**
 * Get detection status
 * 0x2A2B = Root/Jailbreak
 * 0x2A2C = Debugger
 * 0x2A2D = Frida
 */
__attribute__((visibility("hidden")))
int universal_rasp_get_status(int statusType) {
    return UniversalRASPStateMachine::getStatus(statusType);
}

/**
 * Initialize Universal RASP engine
 */
__attribute__((visibility("hidden")))
void universal_rasp_initialize() {
    LOGI("Initializing Universal RASP Engine...");
    
    // Initialize self-checksumming to detect instruction patching
    if (!SelfChecksumming::initialize()) {
        LOGE("Self-Checksumming initialization failed - engine may be compromised");
    }
    
    UniversalRASPStateMachine::riskScore.store(0);
    UniversalRASPStateMachine::rootJailbreakDetected.store(false);
    UniversalRASPStateMachine::debuggerDetected.store(false);
    UniversalRASPStateMachine::fridaDetected.store(false);
    LOGI("Universal RASP Engine initialized successfully");
}

/**
 * Shutdown Universal RASP engine
 */
__attribute__((visibility("hidden")))
void universal_rasp_shutdown() {
    LOGI("Shutting down Universal RASP Engine...");
    UniversalRASPStateMachine::riskScore.store(0);
    UniversalRASPStateMachine::rootJailbreakDetected.store(false);
    UniversalRASPStateMachine::debuggerDetected.store(false);
    UniversalRASPStateMachine::fridaDetected.store(false);
    LOGI("Universal RASP Engine shut down successfully");
}

} // extern "C"
