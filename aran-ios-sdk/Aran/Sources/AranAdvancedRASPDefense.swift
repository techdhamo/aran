import Foundation
import Darwin
import Security
import CommonCrypto

/**
 * Advanced RASP (Runtime Application Self-Protection) Defense for iOS
 * Implements advanced architectural patterns to detect sophisticated attacks
 */
public class AranAdvancedRASPDefense {
    
    public static let shared = AranAdvancedRASPDefense()
    
    private var initialized = false
    
    // ============================================
    // ADVANCED RASP PATTERN 1: Dual-Thread Heartbeat
    // ============================================
    
    /**
     * Shared heartbeat data
     */
    private struct HeartbeatData {
        var lastTimestamp: UInt64
        var thread1Running: Bool
        var thread2Running: Bool
        var heartbeatFailed: Bool
        var failureThresholdMs: UInt64
    }
    
    private var heartbeatData = HeartbeatData(
        lastTimestamp: 0,
        thread1Running: false,
        thread2Running: false,
        heartbeatFailed: false,
        failureThresholdMs: 100 // 100ms threshold
    )
    
    private var heartbeatTimer1: DispatchSourceTimer?
    private var heartbeatTimer2: DispatchSourceTimer?
    
    /**
     * Heartbeat writer (simulated with timer)
     */
    private func startHeartbeatWriter() {
        heartbeatData.thread1Running = true
        
        heartbeatTimer1 = DispatchSource.makeTimerSource(flags: .strict, queue: .global(qos: .userInteractive))
        
        heartbeatTimer1?.schedule(deadline: .now(), repeating: .milliseconds(10)) { [weak self] _ in
            guard let self = self, self.heartbeatData.thread1Running else { return }
            
            // Get current timestamp in nanoseconds
            let timestamp = DispatchTime.now().uptimeNanoseconds
            self.heartbeatData.lastTimestamp = timestamp
        }
        
        heartbeatTimer1?.resume()
        aran_log("Heartbeat writer started")
    }
    
    /**
     * Heartbeat verifier
     */
    private func startHeartbeatVerifier() {
        heartbeatData.thread2Running = true
        
        heartbeatTimer2 = DispatchSource.makeTimerSource(flags: .strict, queue: .global(qos: .userInteractive))
        
        var lastCheck = heartbeatData.lastTimestamp
        
        heartbeatTimer2?.schedule(deadline: .now(), repeating: .milliseconds(50)) { [weak self] _ in
            guard let self = self, self.heartbeatData.thread2Running else { return }
            
            let current = self.heartbeatData.lastTimestamp
            let diffMs = (current - lastCheck) / 1_000_000
            
            // If timestamp hasn't updated within threshold, heartbeat failed
            if diffMs > self.heartbeatData.failureThresholdMs {
                aran_log("Heartbeat failure: timestamp not updating for \(diffMs) ms")
                self.heartbeatData.heartbeatFailed = true
                
                // Trigger silent failure
                aran_log("Silent failure triggered due to heartbeat failure")
                self.triggerSilentFailure(level: 1)
            }
            
            lastCheck = current
        }
        
        heartbeatTimer2?.resume()
        aran_log("Heartbeat verifier started")
    }
    
    /**
     * Stop heartbeat threads
     */
    private func stopHeartbeat() {
        heartbeatData.thread1Running = false
        heartbeatData.thread2Running = false
        
        heartbeatTimer1?.cancel()
        heartbeatTimer1 = nil
        
        heartbeatTimer2?.cancel()
        heartbeatTimer2 = nil
        
        aran_log("Heartbeat stopped")
    }
    
    // ============================================
    // ADVANCED RASP PATTERN 2: Page Table Integrity
    // ============================================
    
    /**
     * Check page table integrity using vmmap
     * Detects code injection by looking for anonymous executable memory
     */
    public func checkPageTableIntegrity() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/vmmap"
        task.arguments = ["--wide", "--all", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        var injectionDetected = false
        
        // Check for anonymous executable segments
        let lines = output.components(separatedBy: "\n")
        for line in lines {
            if line.contains("r-x") && (line.contains("anonymous") || line.contains("???")) {
                aran_log("Anonymous executable memory detected: \(line)")
                injectionDetected = true
            }
            
            // Check for writable executable segments
            if line.contains("rwx") || line.contains("r-x/w") {
                aran_log("Writable executable segment detected: \(line)")
                injectionDetected = true
            }
        }
        
        return injectionDetected
    }
    
    // ============================================
    // ADVANCED RASP PATTERN 3: Inline Hook Detection
    // ============================================
    
    /**
     * Stored original function bytes
     */
    private struct FunctionIntegrity {
        var functionAddress: UnsafeRawPointer
        var originalBytes: [UInt32]
        var checksum: UInt32
        var verified: Bool
    }
    
    private var protectedFunctions: [FunctionIntegrity] = []
    
    /**
     * Calculate checksum of function bytes
     */
    private func calculateFunctionChecksum(_ funcAddr: UnsafeRawPointer, _ size: Int) -> UInt32 {
        var checksum: UInt32 = 0
        let data = funcAddr.assumingMemoryBound(to: UInt8.self)
        
        for i in 0..<size {
            checksum = (checksum << 1) | (checksum >> 31)
            checksum += UInt32(data[i])
        }
        
        return checksum
    }
    
    /**
     * Register a function for integrity monitoring
     */
    private func registerFunctionProtection(_ funcAddr: UnsafeRawPointer) {
        let instructions = funcAddr.assumingMemoryBound(to: UInt32.self)
        
        var integrity = FunctionIntegrity(
            functionAddress: funcAddr,
            originalBytes: [instructions[0], instructions[1]],
            checksum: calculateFunctionChecksum(funcAddr, 16),
            verified: true
        )
        
        protectedFunctions.append(integrity)
        aran_log("Registered function protection for address: \(funcAddr)")
    }
    
    /**
     * Verify function integrity
     */
    private func verifyFunctionIntegrity(_ funcAddr: UnsafeRawPointer) -> Bool {
        let instructions = funcAddr.assumingMemoryBound(to: UInt32.self)
        
        for i in 0..<protectedFunctions.count {
            if protectedFunctions[i].functionAddress == funcAddr {
                // Compare first 8 bytes
                if instructions[0] != protectedFunctions[i].originalBytes[0] ||
                   instructions[1] != protectedFunctions[i].originalBytes[1] {
                    aran_log("Function integrity compromised at \(funcAddr)")
                    protectedFunctions[i].verified = false
                    return false
                }
                
                // Verify checksum
                let currentChecksum = calculateFunctionChecksum(funcAddr, 16)
                if currentChecksum != protectedFunctions[i].checksum {
                    aran_log("Function checksum mismatch at \(funcAddr)")
                    protectedFunctions[i].verified = false
                    return false
                }
                
                protectedFunctions[i].verified = true
                return true
            }
        }
        
        return false
    }
    
    /**
     * Verify all protected functions
     */
    private func verifyAllFunctions() -> Int {
        var compromisedCount = 0
        
        for funcIntegrity in protectedFunctions {
            if !verifyFunctionIntegrity(funcIntegrity.functionAddress) {
                compromisedCount += 1
            }
        }
        
        if compromisedCount > 0 {
            aran_log("\(compromisedCount) functions have been compromised")
        }
        
        return compromisedCount
    }
    
    // ============================================
    // ADVANCED RASP PATTERN 4: Silent Failures
    // ============================================
    
    private var silentFailureTriggered = false
    private var corruptionLevel = 0
    
    /**
     * Trigger silent failure
     */
    private func triggerSilentFailure(level: Int) {
        silentFailureTriggered = true
        corruptionLevel = level
        aran_log("Silent failure triggered at level \(level)")
        
        // Don't crash immediately
        // Instead, return random errors later in execution flow
    }
    
    /**
     * Check if silent failure is active
     */
    public func isSilentFailureActive() -> Bool {
        return silentFailureTriggered
    }
    
    /**
     * Get corruption level
     */
    public func getCorruptionLevel() -> Int {
        return corruptionLevel
    }
    
    // ============================================
    // ADVANCED RASP PATTERN 5: Self-Checksumming
    // ============================================
    
    private var initialRASPChecksum: UInt32 = 0
    
    /**
     * Calculate checksum of RASP code itself
     */
    private func calculateRASPChecksum() -> UInt32 {
        // Get address of this function
        let funcAddr = UnsafeRawPointer(calculateRASPChecksum)
        
        // Calculate checksum of first 1KB of code
        return calculateFunctionChecksum(funcAddr, 1024)
    }
    
    /**
     * Initialize RASP self-checksum
     */
    private func initializeRASPSelfChecksum() {
        initialRASPChecksum = calculateRASPChecksum()
        aran_log("Initial RASP checksum: \(initialRASPChecksum)")
    }
    
    /**
     * Verify RASP self-integrity
     */
    private func verifyRASPIntegrity() -> Bool {
        let currentChecksum = calculateRASPChecksum()
        
        if currentChecksum != initialRASPChecksum {
            aran_log("RASP self-integrity compromised: expected \(initialRASPChecksum), got \(currentChecksum)")
            return false
        }
        
        return true
    }
    
    // ============================================
    // Public API
    // ============================================
    
    /**
     * Initialize all advanced RASP defense patterns
     * @param thresholdMs Heartbeat failure threshold in milliseconds (default 100ms)
     */
    public func initialize(thresholdMs: UInt64 = 100) {
        guard !initialized else {
            aran_log("Advanced RASP defense already initialized")
            return
        }
        
        aran_log("Initializing advanced RASP defense patterns...")
        
        // Initialize heartbeat
        heartbeatData.failureThresholdMs = thresholdMs
        heartbeatData.heartbeatFailed = false
        startHeartbeatWriter()
        startHeartbeatVerifier()
        
        // Initialize RASP self-checksum
        initializeRASPSelfChecksum()
        
        // Register common libSystem functions for protection
        if let libSystem = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY) {
            if let strstrAddr = dlsym(libSystem, "strstr") {
                registerFunctionProtection(UnsafeRawPointer(strstrAddr))
            }
            if let openAddr = dlsym(libSystem, "open") {
                registerFunctionProtection(UnsafeRawPointer(openAddr))
            }
            dlclose(libSystem)
        }
        
        initialized = true
        aran_log("Advanced RASP defense patterns initialized successfully")
    }
    
    /**
     * Check heartbeat status
     */
    public func checkHeartbeat() -> Bool {
        let failed = heartbeatData.heartbeatFailed
        aran_log("Heartbeat check: \(failed ? "FAILED" : "OK")")
        return failed
    }
    
    /**
     * Check page table integrity
     */
    public func checkPageTableIntegrityNative() -> Bool {
        let compromised = checkPageTableIntegrity()
        aran_log("Page table integrity: \(compromised ? "COMPROMISED" : "OK")")
        return compromised
    }
    
    /**
     * Verify function integrity
     */
    public func verifyFunctionIntegrityNative() -> Bool {
        let compromised = verifyAllFunctions()
        aran_log("Function integrity: \(compromised > 0 ? "COMPROMISED" : "OK")")
        return compromised > 0
    }
    
    /**
     * Trigger silent failure
     */
    public func triggerSilentFailureNative(level: Int = 1) {
        triggerSilentFailure(level: level)
    }
    
    /**
     * Verify RASP self-integrity
     */
    public func verifyRASPIntegrityNative() -> Bool {
        let ok = verifyRASPIntegrity()
        aran_log("RASP self-integrity: \(ok ? "OK" : "COMPROMISED")")
        return ok
    }
    
    /**
     * Perform comprehensive advanced RASP check
     */
    public func performComprehensiveAdvancedRASPCheck() -> AdvancedRASPResult {
        aran_log("========================================")
        aran_log("Starting Comprehensive Advanced RASP Check")
        aran_log("========================================")
        
        var result = AdvancedRASPResult()
        
        // Check 1: Heartbeat status
        aran_log("Check 1: Dual-thread heartbeat...")
        result.heartbeatFailed = checkHeartbeat()
        
        // Check 2: Page table integrity
        aran_log("Check 2: Page table integrity...")
        result.pageTableCompromised = checkPageTableIntegrityNative()
        
        // Check 3: Function integrity
        aran_log("Check 3: Function integrity...")
        result.functionIntegrityCompromised = verifyFunctionIntegrityNative()
        
        // Check 4: RASP self-integrity
        aran_log("Check 4: RASP self-integrity...")
        result.raspIntegrityCompromised = !verifyRASPIntegrityNative()
        
        // Check 5: Silent failure status
        aran_log("Check 5: Silent failure status...")
        result.silentFailureActive = isSilentFailureActive()
        result.corruptionLevel = getCorruptionLevel()
        
        // Calculate overall threat level
        result.threatsDetected = [
            result.heartbeatFailed,
            result.pageTableCompromised,
            result.functionIntegrityCompromised,
            result.raspIntegrityCompromised,
            result.silentFailureActive
        ].filter { $0 }.count
        
        result.securityBreach = result.threatsDetected > 0
        
        aran_log("========================================")
        aran_log("Advanced RASP check complete")
        aran_log("Threats detected: \(result.threatsDetected)")
        aran_log("Security breach: \(result.securityBreach)")
        aran_log("========================================")
        
        return result
    }
    
    /**
     * Shutdown all advanced RASP defense patterns
     */
    public func shutdown() {
        aran_log("Shutting down advanced RASP defense patterns...")
        
        stopHeartbeat()
        
        initialized = false
        aran_log("Advanced RASP defense patterns shut down successfully")
    }
    
    /**
     * Check if advanced RASP defense is initialized
     */
    public func isInitialized() -> Bool {
        return initialized
    }
    
    /**
     * Reset initialization state (for testing)
     */
    public func reset() {
        initialized = false
    }
    
    /**
     * Advanced RASP check result
     */
    public struct AdvancedRASPResult {
        public var securityBreach = false
        public var threatsDetected = 0
        public var heartbeatFailed = false
        public var pageTableCompromised = false
        public var functionIntegrityCompromised = false
        public var raspIntegrityCompromised = false
        public var silentFailureActive = false
        public var corruptionLevel = 0
        
        public var description: String {
            return "AdvancedRASPResult { securityBreach=\(securityBreach), threatsDetected=\(threatsDetected) }"
        }
    }
}
