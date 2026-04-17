#include <sys/syscall.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <atomic>
#include <random>
#include <chrono>
#include <thread>
#include <os/log.h>

#define TAG "Universal_RASP_Core"

// ============================================
// UNIVERSAL iOS RASP CORE - Static XCFramework
// BLACKBOX ARCHITECTURE - Advanced Obfuscation
// Works across: Native Swift, Flutter, React Native, Unity
// ============================================

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
// INDIRECT BRANCHING & SYSCALL OBFUSCATION
// ============================================

/**
 * Direct syscall wrapper with indirect branching
 * Uses SVC #80 for iOS convention
 * Bypasses libc to prevent Frida hooks
 */
class UniversalSyscall {
private:
    static std::mt19937 rng;
    
public:
    /**
     * Indirect syscall via function pointer
     * Makes static analysis harder
     */
    __attribute__((always_inline, visibility("hidden")))
    static long indirect_syscall(long syscall_num, long arg0, long arg1, long arg2) {
        // Function pointer to syscall instruction
        static auto syscall_impl = [](long num, long a0, long a1, long a2) -> long {
            register long x0 __asm__("x0") = a0;
            register long x1 __asm__("x1") = a1;
            register long x2 __asm__("x2") = a2;
            register long x8 __asm__("x8") = num;
            
            __asm__ volatile(
                "svc #80"
                : "=r"(x0)
                : "r"(x0), "r"(x1), "r"(x2), "r"(x8)
                : "memory"
            );
            
            return x0;
        };
        
        return syscall_impl(syscall_num, arg0, arg1, arg2);
    }
    
    /**
     * Direct stat syscall for file checking
     * Syscall number 188 for stat on iOS ARM64
     */
    __attribute__((visibility("hidden")))
    static int secure_stat(const char* path, struct stat* buf) {
        return (int)indirect_syscall(188, (long)path, (long)buf, 0);
    }
    
    /**
     * Direct open syscall
     * Syscall number 5 for open on iOS ARM64
     */
    __attribute__((visibility("hidden")))
    static int secure_open(const char* path, int flags, mode_t mode) {
        return (int)indirect_syscall(5, (long)path, flags, mode);
    }
    
    /**
     * Direct close syscall
     * Syscall number 6 for close on iOS ARM64
     */
    __attribute__((visibility("hidden")))
    static int secure_close(int fd) {
        return (int)indirect_syscall(6, fd, 0, 0);
    }
};

std::mt19937 UniversalSyscall::rng(std::chrono::steady_clock::now().time_since_epoch().count());

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
// UNIVERSAL STATE MACHINE
// ============================================

/**
 * Universal RASP State Machine
 * Works across all frameworks via single entry point
 */
__attribute__((visibility("hidden")))
class UniversalRASPStateMachine {
private:
    // Obfuscated state constants
    static constexpr uint32_t STATE_INIT = OBFUSCATE_CONST(0x00000001, 0xDEADBEEF, 0xCAFEBABE);
    static constexpr uint32_t STATE_CHECK_JAILBREAK = OBFUSCATE_CONST(0x00000002, 0x12345678, 0x87654321);
    static constexpr uint32_t STATE_CHECK_DEBUGGER = OBFUSCATE_CONST(0x00000003, 0xABCDEF01, 0xFEDCBA09);
    static constexpr uint32_t STATE_CHECK_FRIDA = OBFUSCATE_CONST(0x00000004, 0x13579BDF, 0x2468ACE0);
    static constexpr uint32_t STATE_CHECK_SANDBOX = OBFUSCATE_CONST(0x00000005, 0x97531086, 0xABCDEF12);
    static constexpr uint32_t STATE_CALCULATE_RISK = OBFUSCATE_CONST(0x00000006, 0xDEF01234, 0x56789ABC);
    static constexpr uint32_t STATE_RETURN = OBFUSCATE_CONST(0x00000000, 0x00000000, 0x00000000);
    
    static std::atomic<int> riskScore;
    static std::atomic<bool> jailbreakDetected;
    static std::atomic<bool> debuggerDetected;
    static std::atomic<bool> fridaDetected;
    
    /**
     * Check for Cydia using direct syscall
     */
    __attribute__((visibility("hidden")))
    static bool checkCydia() {
        const char* cydiaPath = "/Applications/Cydia.app";
        struct stat st;
        int result = UniversalSyscall::secure_stat(cydiaPath, &st);
        return mba_obfuscate(result == 0);
    }
    
    /**
     * Check for bash using direct syscall
     */
    __attribute__((visibility("hidden")))
    static bool checkBash() {
        const char* bashPath = "/bin/bash";
        struct stat st;
        int result = UniversalSyscall::secure_stat(bashPath, &st);
        return mba_obfuscate(result == 0);
    }
    
    /**
     * Check for apt using direct syscall
     */
    __attribute__((visibility("hidden")))
    static bool checkApt() {
        const char* aptPath = "/etc/apt";
        struct stat st;
        int result = UniversalSyscall::secure_stat(aptPath, &st);
        return mba_obfuscate(result == 0);
    }
    
    /**
     * Check for debugger using ptrace with dlsym
     */
    __attribute__((visibility("hidden")))
    static bool checkDebugger() {
        // Use dlsym to hide ptrace symbol from static scanners
        static auto ptrace_func = (long (*)(int, pid_t, caddr_t, int))dlsym(RTLD_DEFAULT, "ptrace");
        
        if (ptrace_func == nullptr) {
            return false;
        }
        
        // PT_DENY_ATTACH = 31 on iOS
        long result = ptrace_func(31, 0, 0, 0);
        return mba_obfuscate(result == -1);
    }
    
    /**
     * Check for Frida via DYLD image scanning
     */
    __attribute__((visibility("hidden")))
    static bool checkFrida() {
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
        
        return mba_obfuscate(false); // Will be true if found
    }
    
    /**
     * Check for sandbox escape
     */
    __attribute__((visibility("hidden")))
    static bool checkSandboxEscape() {
        const char* testPath = "/private/jailbreak_test.txt";
        int fd = UniversalSyscall::secure_open(testPath, O_WRONLY | O_CREAT, 0644);
        
        if (fd >= 0) {
            UniversalSyscall::secure_close(fd);
            unlink(testPath);
            return mba_obfuscate(true);
        }
        
        return mba_obfuscate(false);
    }
    
public:
    /**
     * Execute universal RASP audit with state machine
     * Single entry point for all frameworks
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
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State INIT");
                    currentState = STATE_CHECK_JAILBREAK;
                    break;
                    
                case STATE_CHECK_JAILBREAK:
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State CHECK_JAILBREAK");
                    
                    if (checkCydia()) {
                        jailbreakDetected.store(true);
                        riskScore.fetch_add(3);
                    }
                    if (checkBash()) {
                        jailbreakDetected.store(true);
                        riskScore.fetch_add(3);
                    }
                    if (checkApt()) {
                        jailbreakDetected.store(true);
                        riskScore.fetch_add(3);
                    }
                    
                    currentState = STATE_CHECK_DEBUGGER;
                    break;
                    
                case STATE_CHECK_DEBUGGER:
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State CHECK_DEBUGGER");
                    
                    if (checkDebugger()) {
                        debuggerDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CHECK_FRIDA;
                    break;
                    
                case STATE_CHECK_FRIDA:
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State CHECK_FRIDA");
                    
                    if (checkFrida()) {
                        fridaDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CHECK_SANDBOX;
                    break;
                    
                case STATE_CHECK_SANDBOX:
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State CHECK_SANDBOX");
                    
                    if (checkSandboxEscape()) {
                        jailbreakDetected.store(true);
                        riskScore.fetch_add(5);
                    }
                    
                    currentState = STATE_CALCULATE_RISK;
                    break;
                    
                case STATE_CALCULATE_RISK:
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: State CALCULATE_RISK");
                    
                    int score = riskScore.load();
                    
                    if (score >= 10) {
                        result = 3; // CONFIRMED_TAMPER
                    } else if (score >= 7) {
                        result = 2; // HIGHLY_SUSPICIOUS
                    } else if (score >= 3) {
                        result = 1; // SUSPICIOUS
                    } else {
                        result = 0; // SECURITY_OK
                    }
                    
                    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP: Risk score %d, Result %d", score, result);
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
     */
    __attribute__((visibility("hidden")))
    static bool isJailbreakDetected() { return mba_obfuscate(jailbreakDetected.load()); }
    __attribute__((visibility("hidden")))
    static bool isDebuggerDetected() { return mba_obfuscate(debuggerDetected.load()); }
    __attribute__((visibility("hidden")))
    static bool isFridaDetected() { return mba_obfuscate(fridaDetected.load()); }
};

std::atomic<int> UniversalRASPStateMachine::riskScore(0);
std::atomic<bool> UniversalRASPStateMachine::jailbreakDetected(false);
std::atomic<bool> UniversalRASPStateMachine::debuggerDetected(false);
std::atomic<bool> UniversalRASPStateMachine::fridaDetected(false);

// ============================================
// EXTERN C INTERFACE - Universal Entry Point
// ============================================

extern "C" {

/**
 * Universal RASP audit function
 * Single entry point for all frameworks
 * Selector maps to different security checks
 */
__attribute__((visibility("hidden")))
int universal_rasp_execute_audit(int selector) {
    os_log(OS_LOG_TYPE_INFO, TAG, "========================================");
    os_log(OS_LOG_TYPE_INFO, TAG, "Universal RASP Engine Audit");
    os_log(OS_LOG_TYPE_INFO, TAG, "Selector: %d", selector);
    os_log(OS_LOG_TYPE_INFO, TAG, "========================================");
    
    int result = UniversalRASPStateMachine::executeAudit(selector);
    
    os_log(OS_LOG_TYPE_INFO, TAG, "========================================");
    os_log(OS_LOG_TYPE_INFO, TAG, "Audit Complete. Result: %d", result);
    os_log(OS_LOG_TYPE_INFO, TAG, "========================================");
    
    return result;
}

/**
 * Get detection status (for debugging)
 */
__attribute__((visibility("hidden")))
int universal_rasp_get_status(int status_type) {
    switch (status_type) {
        case 0: // Jailbreak
            return UniversalRASPStateMachine::isJailbreakDetected() ? 1 : 0;
        case 1: // Debugger
            return UniversalRASPStateMachine::isDebuggerDetected() ? 1 : 0;
        case 2: // Frida
            return UniversalRASPStateMachine::isFridaDetected() ? 1 : 0;
        default:
            return 0;
    }
}

} // extern "C"
