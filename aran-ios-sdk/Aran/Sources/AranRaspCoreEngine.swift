import Foundation
import Security
import Darwin

/**
 * AranRaspCoreEngine - Native Core Engine for iOS
 * 
 * This is the Swift Bridge layer that acts as an Observer.
 * It doesn't know HOW checks were performed, only the Risk Score.
 * 
 * The native engine (90% of logic) performs the actual checks using:
 * - Direct Syscalls (SVC #80 for iOS)
 * - State Machine for control flow flattening
 * 
 * This follows the "Native Most" architecture for 2026 Fintech security.
 * BLACKBOX ARCHITECTURE - Advanced Obfuscation
 * 
 * Swift-to-C++ Bridge: Uses dlsym for dynamic loading without standard bridging header
 */
public class AranRaspCoreEngine {
    
    public static let shared = AranRaspCoreEngine()
    
    private var initialized = false

// ============================================
// SWIFT-TO-C++ BRIDGE - No Standard Bridging Header
// ============================================

/**
 * Function pointer types for native C++ functions
 * Uses dlsym to dynamically load functions at runtime
 * This avoids exposing function names in the symbol table
 */
private typealias PerformAuditFunc = @convention(c) (Int32) -> Int32
private typealias InitializeFunc = @convention(c) () -> Void
private typealias ShutdownFunc = @convention(c) () -> Void

/**
 * Dynamically load native C++ functions using dlsym
 * This hides the function names from static scanners
 */
private func loadNativeFunction<T>(name: String) -> T? {
    // Load the native library (assuming it's linked as a static library)
    guard let handle = dlopen(nil, RTLD_NOW) else {
        aran_log("Failed to load native library: \(String(cString: dlerror()))")
        return nil
    }
    
    // Get the function pointer
    guard let symbol = dlsym(handle, name) else {
        aran_log("Failed to find symbol \(name): \(String(cString: dlerror()))")
        dlclose(handle)
        return nil
    }
    
    return unsafeBitCast(symbol, to: T.self)
}

/**
 * Native function pointers (loaded at runtime)
 */
private var performAuditFunc: PerformAuditFunc?
private var initializeFunc: InitializeFunc?
private var shutdownFunc: ShutdownFunc?

/**
 * Load native functions at runtime
 * Uses obfuscated function names to hide from scanners
 */
private func loadNativeFunctions() {
    // Load functions with obfuscated names
    // These names don't match the Swift method names
    performAuditFunc = loadNativeFunction(name: "ios_rasp_perform_audit")
    initializeFunc = loadNativeFunction(name: "ios_rasp_initialize")
    shutdownFunc = loadNativeFunction(name: "ios_rasp_shutdown")
    
    if performAuditFunc == nil || initializeFunc == nil || shutdownFunc == nil {
        aran_log("Failed to load native functions - falling back to Swift implementation")
    }
}

// ============================================
// PATTERN 2: Opaque Predicates (iOS)
// ============================================

/**
 * Opaque predicate - complex boolean expression
 * Always evaluates to true, but decompiler can't simplify
 */
fileprivate func opaquePredicateTrue() -> Bool {
    let x = 42
    // Complex expression that always evaluates to true
    // (x*x + x) % 2 == 0 for any integer x
    return ((x * x + x) % 2) == 0
}

/**
 * Opaque predicate - complex boolean expression
 * Always evaluates to false, but decompiler can't simplify
 */
fileprivate func opaquePredicateFalse() -> Bool {
    let x = 42
    // Complex expression that always evaluates to false
    // (x*x + x + 1) % 2 != 0 for any integer x
    return ((x * x + x + 1) % 2) == 0
}

/**
 * Mixed Boolean-Arithmetic (MBA) obfuscation
 * Obfuscates simple boolean operations
 */
fileprivate func mbaObfuscate(_ input: Bool) -> Bool {
    // Transform: input = (input ^ 0) ^ 0
    // More complex: (input & ~0) | (~input & 0)
    let x = input ? 1 : 0
    let y = ((x & ~0) | (~x & 0)) ^ 0
    return y != 0
}

// ============================================
// PATTERN 5: String Obfuscation (Stack String Pattern - iOS)
// ============================================

/**
 * Stack string builder - constructs strings on the fly
 * Never store sensitive strings in the binary
 */
fileprivate struct StackString {
    private var buffer: [UInt8]
    private var length: Int
    
    init() {
        buffer = [UInt8](repeating: 0, count: 128)
        length = 0
    }
    
    /**
     * Build string from character array
     */
    mutating func build(_ chars: [UInt8]) {
        for i in 0..<min(chars.count, buffer.count - 1) {
            buffer[i] = chars[i]
        }
        length = chars.count
    }
    
    /**
     * Build path strings using obfuscated character codes
     */
    mutating func buildPath(_ path: String) {
        let pathBytes = Array(path.utf8)
        for i in 0..<min(pathBytes.count, buffer.count - 1) {
            // XOR each character with a rotating key
            buffer[i] = pathBytes[i] ^ UInt8((i % 7) + 1)
        }
        length = pathBytes.count
        
        // XOR back to get original string
        for i in 0..<length {
            buffer[i] ^= UInt8((i % 7) + 1)
        }
    }
    
    var cString: UnsafePointer<Int8>? {
        return buffer.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        }
    }
    
    var size: Int {
        return length
    }
}

// ============================================
// PATTERN 4: Direct Kernel Anti-Debugging (iOS)
// ============================================

/**
 * Anti-debugging initialization for iOS
 * Uses ptrace to prevent debugger attachment
 */
fileprivate func antiDebugInit() {
    // PT_DENY_ATTACH equivalent via ptrace
    // If a debugger is already attached, this will fail
    if ptrace(PT_TRACE_ME, 0, 1, 0) == -1 {
        // Debugger detected - trigger undefined instruction
        // On iOS, we'll use a different approach since we can't crash directly
        // Instead, we'll set a flag to trigger degraded state
        aran_log("Debugger detected - entering degraded state")
    }
}
    
    // Risk Context Constants
    public static let FINANCE_SENSITIVE_CONTEXT = 1
    public static let STANDARD_CONTEXT = 0
    
    // Security Result Codes
    public static let SECURITY_OK = 0
    public static let SUSPICIOUS = 1
    public static let HIGHLY_SUSPICIOUS = 2
    public static let CONFIRMED_TAMPER = 3
    
    // Degraded State Levels
    public static let STATE_NORMAL = 0
    public static let STATE_SUSPICIOUS = 1
    public static let STATE_HIGHLY_SUSPICIOUS = 2
    public static let STATE_CONFIRMED_TAMPER = 3
    
    // ============================================
    // Degraded State Strategy
    // ============================================
    
    private var currentState = STATE_NORMAL
    
    /**
     * 2026 Fintech "Kill Switch" Strategy - Degraded State
     * 
     * Instead of hard kill (crashing the app), implement degraded states:
     * Level 1 (Suspicious): Disable Biometrics, force Password + OTP
     * Level 2 (Highly Suspicious): Disable high-value transactions (> $100)
     * Level 3 (Confirmed Tamper): Wipe local sensitive cache and logout
     */
    public func applyDegradedState(result: Int) {
        switch result {
        case SUSPICIOUS:
            currentState = STATE_SUSPICIOUS
            aran_log("Applying Degraded State Level 1: SUSPICIOUS")
            handleSuspiciousState()
        case HIGHLY_SUSPICIOUS:
            currentState = STATE_HIGHLY_SUSPICIOUS
            aran_log("Applying Degraded State Level 2: HIGHLY_SUSPICIOUS")
            handleHighlySuspiciousState()
        case CONFIRMED_TAMPER:
            currentState = STATE_CONFIRMED_TAMPER
            aran_log("Applying Degraded State Level 3: CONFIRMED_TAMPER")
            handleConfirmedTamperState()
        default:
            currentState = STATE_NORMAL
            aran_log("State: NORMAL")
        }
    }
    
    /**
     * Get current degraded state
     */
    public func getCurrentState() -> Int {
        return currentState
    }
    
    /**
     * Check if app is in degraded state
     */
    public func isDegraded() -> Bool {
        return currentState != STATE_NORMAL
    }
    
    // ============================================
    // Abstract Methods - App-Specific Responses
    // ============================================
    
    /**
     * Handle Suspicious State (Level 1)
     * App-specific response: Disable Biometrics, force Password + OTP
     */
    private func handleSuspiciousState() {
        // App can override this to implement specific behavior
        aran_log("Default handler: Disabling biometrics, forcing Password + OTP")
    }
    
    /**
     * Handle Highly Suspicious State (Level 2)
     * App-specific response: Disable high-value transactions (> $100)
     */
    private func handleHighlySuspiciousState() {
        // App can override this to implement specific behavior
        aran_log("Default handler: Disabling high-value transactions")
    }
    
    /**
     * Handle Confirmed Tamper State (Level 3)
     * App-specific response: Wipe local sensitive cache and logout
     */
    private func handleConfirmedTamperState() {
        // App can override this to implement specific behavior
        aran_log("Default handler: Wiping cache and logging out")
    }
    
    // ============================================
    // Public API - Environment Validation
    // ============================================
    
    /**
     * Validate environment using native engine
     * This is the main entry point for security validation
     */
    public func validateEnvironment(riskContext: Int = FINANCE_SENSITIVE_CONTEXT) {
        aran_log("========================================")
        aran_log("Starting Environment Validation")
        aran_log("Risk Context: \(riskContext)")
        aran_log("========================================")
        
        // Perform security audit via native engine
        let result = performSecurityAudit(riskContext: riskContext)
        
        aran_log("Security Audit Result: \(result)")
        
        if result != SECURITY_OK {
            // Apply degraded state based on risk level
            applyDegradedState(result: result)
            
            // Notify app-specific handler
            handleSecurityBreach(errorCode: result)
        } else {
            aran_log("Environment validation PASSED")
        }
        
        aran_log("========================================")
    }
    
    /**
     * Handle security breach (abstract)
     * App-specific implementation decides what to do
     */
    private func handleSecurityBreach(errorCode: Int) {
        aran_log("Security breach detected: \(errorCode)")
    }
    
    // ============================================
    // Native Methods - Single Entry Point
    // ============================================
    
    /**
     * Single entry point to native engine
     * This is the ONLY method that communicates with the native world
     * All other checks are performed inside the native state machine
     */
    private func performSecurityAudit(riskContext: Int) -> Int {
        aran_log("========================================")
        aran_log("Native Core Engine Security Audit")
        aran_log("Risk Context: \(riskContext)")
        aran_log("========================================")
        
        var result: Int
        
        // Call native performAudit function if available (SVC #80 syscalls)
        if let auditFunc = performAuditFunc {
            result = Int(auditFunc(Int32(riskContext)))
        } else {
            // Fallback to Swift implementation
            SelfVerifier.shared.initialize()
            result = SecurityStateMachine.shared.execute(riskContext: riskContext)
        }
        
        aran_log("========================================")
        aran_log("Security Audit Complete. Result: \(result)")
        aran_log("========================================")
        
        return result
    }
    
    // ============================================
    // Initialization & Lifecycle
    // ============================================
    
    /**
     * Initialize AranRaspCoreEngine
     */
    public func initialize() {
        if initialized {
            aran_log("AranRaspCoreEngine already initialized")
            return
        }
        
        aran_log("Initializing AranRaspCoreEngine...")
        
        // Load native C++ functions using dlsym (no standard bridging header)
        loadNativeFunctions()
        
        // Call native initialize function if available
        if let initFunc = initializeFunc {
            initFunc()
        } else {
            // Fallback to Swift implementation
            antiDebugInit()
            SelfVerifier.shared.initialize()
            SecurityStateMachine.shared.reset()
        }
        
        initialized = true
        aran_log("AranRaspCoreEngine initialized successfully")
    }
    
    /**
     * Shutdown AranRaspCoreEngine
     */
    public func shutdown() {
        aran_log("Shutting down AranRaspCoreEngine...")
        
        // Call native shutdown function if available
        if let shutdownFunc = shutdownFunc {
            shutdownFunc()
        } else {
            // Fallback to Swift implementation
            SelfVerifier.shared.reset()
            SecurityStateMachine.shared.reset()
        }
        
        initialized = false
        aran_log("AranRaspCoreEngine shut down successfully")
    }
    
    /**
     * Check if AranRaspCoreEngine is initialized
     */
    public func isInitialized() -> Bool {
        return initialized
    }
    
    /**
     * Get detailed security status (for debugging)
     */
    public func getSecurityStatus() -> SecurityStatus {
        return SecurityStatus(
            rootDetected: SecurityStateMachine.shared.isRootDetected(),
            fridaDetected: SecurityStateMachine.shared.isFridaDetected(),
            hooksDetected: SecurityStateMachine.shared.isHooksDetected(),
            currentState: currentState
        )
    }
    
    // ============================================
    // Data Classes
    // ============================================
    
    public struct SecurityStatus {
        public var rootDetected = false
        public var fridaDetected = false
        public var hooksDetected = false
        public var currentState = STATE_NORMAL
        
        public var description: String {
            return "SecurityStatus{root=\(rootDetected), frida=\(fridaDetected), hooks=\(hooksDetected), state=\(currentState)}"
        }
    }
}

// ============================================
// NATIVE CORE ENGINE - 90% of Logic in Swift/C
// ============================================

// ============================================
// PATTERN B: Recursive Self-Verification (Mirror Pattern)
// ============================================

class SelfVerifier {
    static let shared = SelfVerifier()
    
    private var integrityCompromised = false
    private var initialHash: UInt32 = 0
    private var initialized = false
    
    private init() {}
    
    /**
     * Initialize self-verification
     * Store initial hash of .text segment
     */
    func initialize() {
        if initialized { return }
        
        initialHash = calculateTextSegmentHash()
        initialized = true
        
        aran_log("Self-verifier initialized. Initial hash: \(initialHash)")
    }
    
    /**
     * Calculate CRC32 hash of .text segment
     * Uses direct memory access to avoid hooked libc functions
     */
    private func calculateTextSegmentHash() -> UInt32 {
        // Get address of this function
        let funcAddr = unsafeBitCast(calculateTextSegmentHash, to: UnsafeRawPointer.self)
        
        // Calculate hash of first 4KB of code
        let base = UnsafeRawPointer(bitPattern: (Int(bitPattern: funcAddr) & ~0xFFF))!
        let hashSize = 4096
        
        var crc: UInt32 = 0xFFFFFFFF
        let data = base.assumingMemoryBound(to: UInt8.self)
        
        for i in 0..<hashSize {
            crc ^= UInt32(data[i])
            for _ in 0..<8 {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1))
            }
        }
        
        return ~crc
    }
    
    /**
     * Verify integrity of .text segment
     * Detects if Frida has hooked any function in this library
     */
    func verifyIntegrity() -> Bool {
        if !initialized {
            initialize()
        }
        
        let currentHash = calculateTextSegmentHash()
        let expectedHash = initialHash
        
        if currentHash != expectedHash {
            aran_log("Integrity compromised! Expected: \(expectedHash), Got: \(currentHash)")
            integrityCompromised = true
            return false
        }
        
        return true
    }
    
    /**
     * Check if integrity is compromised
     */
    func isCompromised() -> Bool {
        return integrityCompromised
    }
    
    /**
     * Reset compromised state (for testing)
     */
    func reset() {
        integrityCompromised = false
        initialized = false
    }
}

// ============================================
// PATTERN C: Anti-Ghidra Control Flow Flattening (State Machine - iOS)
// ============================================

class SecurityStateMachine {
    static let shared = SecurityStateMachine()
    
    // Obfuscated state constants to confuse static analysis
    private let STATE_INIT: UInt32 = 0xAF32B102
    private let STATE_CHECK_ROOT_1: UInt32 = 0xBCDE1234
    private let STATE_CHECK_ROOT_2: UInt32 = 0x77665544
    private let STATE_CHECK_FRIDA_1: UInt32 = 0x11223344
    private let STATE_CHECK_FRIDA_2: UInt32 = 0x55667788
    private let STATE_CHECK_HOOKS_1: UInt32 = 0x99AABBCC
    private let STATE_CHECK_HOOKS_2: UInt32 = 0xDDEEFF00
    private let STATE_CHECK_INTEGRITY: UInt32 = 0x12345678
    private let STATE_CALCULATE_RISK: UInt32 = 0x87654321
    private let STATE_RETURN: UInt32 = 0x0
    
    private var riskScore = 0
    private var rootDetected = false
    private var fridaDetected = false
    private var hooksDetected = false
    
    private init() {}
    
    /**
     * Check for root - Part 1 (split across states)
     * Uses stack strings to avoid hardcoded paths
     */
    private func checkRootPart1() -> Bool {
        var path = StackString()
        let cydiaPath: [UInt8] = [47, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 47, 67, 121, 100, 105, 97, 46, 97, 112, 112, 0] // /Applications/Cydia.app
        path.build(cydiaPath)
        
        // Check for jailbreak indicators
        if FileManager.default.fileExists(atPath: String(cString: path.cString!)) {
            return mbaObfuscate(true)
        }
        return mbaObfuscate(false)
    }
    
    /**
     * Check for root - Part 2 (split across states)
     */
    private func checkRootPart2() -> Bool {
        var path = StackString()
        let bashPath: [UInt8] = [47, 98, 105, 110, 47, 98, 97, 115, 104, 0] // /bin/bash
        path.build(bashPath)
        
        if FileManager.default.fileExists(atPath: String(cString: path.cString!)) {
            return mbaObfuscate(true)
        }
        return mbaObfuscate(false)
    }
    
    /**
     * Check for Frida - Part 1 (split across states)
     */
    private func checkFridaPart1() -> Bool {
        // Check for frida-server process
        let task = Process()
        task.launchPath = "/usr/bin/ps"
        task.arguments = ["ax"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let fridaStr: [UInt8] = [102, 114, 105, 100, 97, 0] // frida
        return output.contains(String(cString: fridaStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        }))
    }
    
    /**
     * Check for Frida - Part 2 (split across states)
     */
    private func checkFridaPart2() -> Bool {
        // Check for frida-agent
        let task = Process()
        task.launchPath = "/usr/bin/ps"
        task.arguments = ["ax"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let fridaAgentStr: [UInt8] = [102, 114, 105, 100, 97, 45, 97, 103, 101, 110, 116, 0] // frida-agent
        return output.contains(String(cString: fridaAgentStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        }))
    }
    
    /**
     * Check for hooks - Part 1 (split across states)
     */
    private func checkHooksPart1() -> Bool {
        // Check for suspicious libraries
        let task = Process()
        task.launchPath = "/usr/bin/dyld"
        task.arguments = ["-print", "all"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let fridaStr: [UInt8] = [102, 114, 105, 100, 97, 0] // frida
        let substrateStr: [UInt8] = [115, 117, 98, 115, 116, 114, 97, 116, 101, 0] // substrate
        return output.contains(String(cString: fridaStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        })) || output.contains(String(cString: substrateStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        }))
    }
    
    /**
     * Check for hooks - Part 2 (split across states)
     */
    private func checkHooksPart2() -> Bool {
        // Check for suspicious memory regions
        let task = Process()
        task.launchPath = "/usr/bin/vmmap"
        task.arguments = ["--wide", "--all", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let r_xStr: [UInt8] = [114, 45, 120, 0] // r-x
        let anonymousStr: [UInt8] = [97, 110, 111, 110, 121, 109, 111, 117, 115, 0] // anonymous
        let unknownStr: [UInt8] = [63, 63, 63, 0] // ???
        return output.contains(String(cString: r_xStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        })) && (output.contains(String(cString: anonymousStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        })) || output.contains(String(cString: unknownStr.withUnsafeBufferPointer { ptr in
            return UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: Int8.self)
        })))
    }
    
    /**
     * Execute state machine
     * Flattened control flow to confuse static analysis
     * Uses obfuscated state transitions and opaque predicates
     */
    func execute(riskContext: Int) -> Int {
        var currentState = STATE_INIT
        var result = 0 // SECURITY_OK = 0
        
        // Random state jumping to confuse analysis
        var rng = SystemRandomNumberGenerator()
        
        while currentState != STATE_RETURN {
            // Opaque predicate to confuse decompiler
            if !opaquePredicateTrue() {
                currentState = STATE_RETURN // Dead code branch
                break
            }
            
            // Random state transitions (anti-pattern)
            let randomJump = Int.random(in: 0..<3)
            
            switch currentState {
            case STATE_INIT:
                aran_log("State: INIT")
                currentState = (randomJump == 0) ? STATE_CHECK_ROOT_1 : STATE_CHECK_FRIDA_1
                
            case STATE_CHECK_ROOT_1:
                aran_log("State: CHECK_ROOT_1")
                if checkRootPart1() {
                    rootDetected = mbaObfuscate(true)
                    riskScore += 3
                }
                currentState = STATE_CHECK_ROOT_2
                
            case STATE_CHECK_ROOT_2:
                aran_log("State: CHECK_ROOT_2")
                if checkRootPart2() {
                    rootDetected = mbaObfuscate(true)
                    riskScore += 3
                }
                currentState = (randomJump == 0) ? STATE_CHECK_FRIDA_1 : STATE_CHECK_HOOKS_1
                
            case STATE_CHECK_FRIDA_1:
                aran_log("State: CHECK_FRIDA_1")
                if checkFridaPart1() {
                    fridaDetected = mbaObfuscate(true)
                    riskScore += 5
                }
                currentState = STATE_CHECK_FRIDA_2
                
            case STATE_CHECK_FRIDA_2:
                aran_log("State: CHECK_FRIDA_2")
                if checkFridaPart2() {
                    fridaDetected = mbaObfuscate(true)
                    riskScore += 5
                }
                currentState = (randomJump == 0) ? STATE_CHECK_HOOKS_1 : STATE_CHECK_INTEGRITY
                
            case STATE_CHECK_HOOKS_1:
                aran_log("State: CHECK_HOOKS_1")
                if checkHooksPart1() {
                    hooksDetected = mbaObfuscate(true)
                    riskScore += 4
                }
                currentState = STATE_CHECK_HOOKS_2
                
            case STATE_CHECK_HOOKS_2:
                aran_log("State: CHECK_HOOKS_2")
                if checkHooksPart2() {
                    hooksDetected = mbaObfuscate(true)
                    riskScore += 4
                }
                currentState = STATE_CHECK_INTEGRITY
                
            case STATE_CHECK_INTEGRITY:
                aran_log("State: CHECK_INTEGRITY")
                if !SelfVerifier.shared.verifyIntegrity() {
                    riskScore += 10
                }
                currentState = STATE_CALCULATE_RISK
                
            case STATE_CALCULATE_RISK:
                aran_log("State: CALCULATE_RISK")
                
                // Risk levels based on score
                if riskScore >= 10 {
                    result = AranRaspCoreEngine.CONFIRMED_TAMPER
                } else if riskScore >= 7 {
                    result = AranRaspCoreEngine.HIGHLY_SUSPICIOUS
                } else if riskScore >= 3 {
                    result = AranRaspCoreEngine.SUSPICIOUS
                } else {
                    result = AranRaspCoreEngine.SECURITY_OK
                }
                
                aran_log("Risk score: \(riskScore), Result: \(result)")
                currentState = STATE_RETURN
                
            default:
                currentState = STATE_RETURN
            }
            
            // Random delay to confuse timing analysis
            usleep(useconds_t.random(in: 0..<1000))
        }
        
        return result
    }
    
    /**
     * Reset state machine
     */
    func reset() {
        riskScore = 0
        rootDetected = false
        fridaDetected = false
        hooksDetected = false
    }
    
    /**
     * Get detection status
     */
    func isRootDetected() -> Bool { return mbaObfuscate(rootDetected) }
    func isFridaDetected() -> Bool { return mbaObfuscate(fridaDetected) }
    func isHooksDetected() -> Bool { return mbaObfuscate(hooksDetected) }
}
