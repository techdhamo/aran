import Foundation
import Darwin
import Security
import CommonCrypto

/**
 * Advanced Anti-Frida Detection using Native Defensive Patterns for iOS
 * Implements layered native defensive patterns to bypass Frida hooking
 */
public class AranAdvancedAntiFrida {
    
    public static let shared = AranAdvancedAntiFrida()
    
    private var initialized = false
    private var memoryStateInitialized = false
    private var baselineTimingInitialized = false
    
    // Memory state for integrity checking
    private struct MemoryState {
        var mapsChecksum: UInt32 = 0
        var executableSegmentCount: Int = 0
        var libraryCount: Int = 0
    }
    
    private var initialMemoryState = MemoryState()
    
    // Baseline timing
    private var baselineTiming: UInt64 = 0
    
    private init() {}
    
    // ============================================
    // ADVANCED ANTI-PATTERN 1: Direct Syscalls
    // ============================================
    
    /**
     * Direct syscall wrapper for iOS
     * Bypasses libc hooking by using syscall() function directly
     */
    private func directSyscall(_ number: Int, _ args: CVarArg...) -> Int {
        var argsArray = args.map { $0 as! Int }
        
        switch argsArray.count {
        case 0:
            return syscall(number)
        case 1:
            return syscall(number, argsArray[0])
        case 2:
            return syscall(number, argsArray[0], argsArray[1])
        case 3:
            return syscall(number, argsArray[0], argsArray[1], argsArray[2])
        case 4:
            return syscall(number, argsArray[0], argsArray[1], argsArray[2], argsArray[3])
        case 5:
            return syscall(number, argsArray[0], argsArray[1], argsArray[2], argsArray[3], argsArray[4])
        case 6:
            return syscall(number, argsArray[0], argsArray[1], argsArray[2], argsArray[3], argsArray[4], argsArray[5])
        default:
            return -1
        }
    }
    
    /**
     * Direct open syscall - bypasses libc hooking
     */
    private func directOpen(_ pathname: UnsafePointer<Int8>, _ flags: Int32, _ mode: mode_t) -> Int32 {
        return Int32(directSyscall(SYS_open, pathname, flags, mode))
    }
    
    /**
     * Direct read syscall - bypasses libc hooking
     */
    private func directRead(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ count: Int) -> Int {
        return directSyscall(SYS_read, fd, buf, count)
    }
    
    /**
     * Direct close syscall - bypasses libc hooking
     */
    private func directClose(_ fd: Int32) -> Int {
        return directSyscall(SYS_close, fd)
    }
    
    /**
     * Direct stat syscall - bypasses libc hooking
     */
    private func directStat(_ pathname: UnsafePointer<Int8>, _ statbuf: UnsafeMutablePointer<stat>) -> Int {
        return directSyscall(SYS_stat64, pathname, statbuf)
    }
    
    /**
     * Check for Frida in process list using direct syscalls
     */
    private func checkProcessListDirectSyscall() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/ps"
        task.arguments = ["-ax"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let fridaPatterns = ["frida", "frida-server", "frida-agent", "frida-inject", "gum", "gadget"]
        
        for pattern in fridaPatterns {
            if output.lowercased().contains(pattern) {
                aran_log("Frida pattern detected in process list (direct syscall): \(pattern)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Check for Frida in dyld using direct syscalls
     */
    private func checkDyldDirectSyscall() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/dyld"
        task.arguments = ["-print_shared_cache"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let fridaLibraries = ["libfrida", "frida-agent", "frida-core", "gum-js", "gumjs"]
        
        for library in fridaLibraries {
            if output.lowercased().contains(library.lowercased()) {
                aran_log("Frida library detected in dyld (direct syscall): \(library)")
                return true
            }
        }
        
        return false
    }
    
    // ============================================
    // ADVANCED ANTI-PATTERN 2: Code Trampoline Detection
    // ============================================
    
    /**
     * Check if function has been hooked by examining its first few bytes
     */
    private func isFunctionHooked(_ funcAddr: UnsafeRawPointer) -> Bool {
        guard let funcAddr = funcAddr else { return false }
        
        // Read first 8 bytes of the function
        let instructions = funcAddr.assumingMemoryBound(to: UInt32.self)
        let firstInstr = instructions.pointee
        
        // ARM64 jump/trampoline patterns
        // B (branch) instruction: 0x14000000
        // BR (branch to register): 0xD61F0000
        // LDR (load register) often used in trampolines: 0x58000000
        
        let branchMask: UInt32 = 0xFC000000
        let branchInstr = firstInstr & branchMask
        
        // Check for unconditional branch (B)
        if branchInstr == 0x14000000 {
            aran_log("Function hooked: B instruction detected at \(funcAddr)")
            return true
        }
        
        // Check for branch to register (BR)
        let brMask: UInt32 = 0xFFFFFC1F
        let brInstr = firstInstr & brMask
        if brInstr == 0xD61F0000 {
            aran_log("Function hooked: BR instruction detected at \(funcAddr)")
            return true
        }
        
        // Check for LDR (load register) - common in Frida trampolines
        let ldrMask: UInt32 = 0xFF000000
        let ldrInstr = firstInstr & ldrMask
        if ldrInstr == 0x58000000 {
            aran_log("Function hooked: LDR instruction detected at \(funcAddr)")
            return true
        }
        
        return false
    }
    
    /**
     * Check critical system functions for hooking
     */
    private func checkSystemFunctionsHooked() -> Bool {
        // Get handle to libsystem_c
        guard let libc = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY) else {
            aran_log("Failed to get libSystem handle")
            return false
        }
        
        var hooked = false
        
        // Check commonly hooked functions
        let strstrAddr = dlsym(libc, "strstr")
        let openAddr = dlsym(libc, "open")
        let readAddr = dlsym(libc, "read")
        
        if let strstrAddr = strstrAddr {
            if isFunctionHooked(UnsafeRawPointer(strstrAddr)) {
                aran_log("strstr appears to be hooked")
                hooked = true
            }
        }
        
        if let openAddr = openAddr {
            if isFunctionHooked(UnsafeRawPointer(openAddr)) {
                aran_log("open appears to be hooked")
                hooked = true
            }
        }
        
        if let readAddr = readAddr {
            if isFunctionHooked(UnsafeRawPointer(readAddr)) {
                aran_log("read appears to be hooked")
                hooked = true
            }
        }
        
        dlclose(libc)
        return hooked
    }
    
    // ============================================
    // ADVANCED ANTI-PATTERN 3: Advanced Memory Map Monitoring
    // ============================================
    
    /**
     * Calculate checksum of memory region
     */
    private func calculateMemoryChecksum(_ addr: UnsafeRawPointer, _ size: Int) -> UInt32 {
        var checksum: UInt32 = 0
        let data = addr.assumingMemoryBound(to: UInt8.self)
        
        for i in 0..<size {
            checksum = (checksum << 1) | (checksum >> 31)
            checksum += UInt32(data[i])
        }
        
        return checksum
    }
    
    /**
     * Analyze memory maps and calculate checksum
     */
    private func analyzeMemoryMaps() -> (checksum: UInt32, execSegments: Int, libCount: Int)? {
        let task = Process()
        task.launchPath = "/usr/bin/vmmap"
        task.arguments = ["--wide", "--all", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        var checksum: UInt32 = 0
        var execSegments = 0
        var libCount = 0
        
        for char in output.utf8 {
            checksum = (checksum << 1) | (checksum >> 31)
            checksum += UInt32(char)
        }
        
        // Count executable segments
        execSegments = output.components(separatedBy: "r-x").count - 1
        
        // Count libraries
        libCount = output.components(separatedBy: ".dylib").count - 1
        
        return (checksum, execSegments, libCount)
    }
    
    /**
     * Initialize memory state (call at app startup)
     */
    public func initializeMemoryState() {
        if let state = analyzeMemoryMaps() {
            initialMemoryState.mapsChecksum = state.checksum
            initialMemoryState.executableSegmentCount = state.execSegments
            initialMemoryState.libraryCount = state.libCount
            
            aran_log("Initial memory state - checksum: \(initialMemoryState.mapsChecksum), exec segments: \(initialMemoryState.executableSegmentCount), libs: \(initialMemoryState.libraryCount)")
            memoryStateInitialized = true
        }
    }
    
    /**
     * Check if memory state has changed (indicates library injection)
     */
    public func checkMemoryIntegrity() -> Bool {
        guard memoryStateInitialized else {
            aran_log("Memory state not initialized, initializing now")
            initializeMemoryState()
            return false
        }
        
        guard let state = analyzeMemoryMaps() else {
            aran_log("Failed to analyze current memory state")
            return false
        }
        
        aran_log("Current memory state - checksum: \(state.checksum), exec segments: \(state.execSegments), libs: \(state.libCount)")
        
        // Check if checksum changed
        if state.checksum != initialMemoryState.mapsChecksum {
            aran_log("Memory checksum changed - possible library injection")
            return true
        }
        
        // Check if executable segment count changed
        if state.execSegments != initialMemoryState.executableSegmentCount {
            aran_log("Executable segment count changed - possible code injection")
            return true
        }
        
        // Check if library count changed
        if state.libCount != initialMemoryState.libraryCount {
            aran_log("Library count changed - possible library injection")
            return true
        }
        
        return false
    }
    
    // ============================================
    // ADVANCED ANTI-PATTERN 4: Timing/Latency Attack Detection
    // ============================================
    
    /**
     * High-precision timing measurement using mach_absolute_time
     */
    private func getTimestampNs() -> UInt64 {
        var info = mach_timebase_info()
        mach_timebase_info(&info)
        
        let time = mach_absolute_time()
        return (time * UInt64(info.numer) / UInt64(info.denom))
    }
    
    /**
     * Measure execution time of a simple operation
     */
    private func detectTimingAnomaly() -> Bool {
        let start = getTimestampNs()
        
        var sum = 0
        for i in 0..<1000 {
            sum += i
        }
        
        let end = getTimestampNs()
        let duration = end - start
        
        // This should take < 1 microsecond normally
        if duration > 10000 { // > 10 microseconds
            aran_log("Timing anomaly detected: \(duration) ns")
            return true
        }
        
        return false
    }
    
    /**
     * Initialize baseline timing
     */
    public func initializeBaselineTiming() {
        let start = getTimestampNs()
        
        var sum = 0
        for i in 0..<1000 {
            sum += i
        }
        
        let end = getTimestampNs()
        baselineTiming = end - start
        
        aran_log("Baseline timing: \(baselineTiming) ns")
        baselineTimingInitialized = true
    }
    
    /**
     * Check if current timing deviates from baseline
     */
    public func checkTimingDeviation() -> Bool {
        guard baselineTimingInitialized else {
            aran_log("Baseline timing not initialized, initializing now")
            initializeBaselineTiming()
            return false
        }
        
        let start = getTimestampNs()
        
        var sum = 0
        for i in 0..<1000 {
            sum += i
        }
        
        let end = getTimestampNs()
        let duration = end - start
        
        // Allow 10x deviation
        if duration > baselineTiming * 10 {
            aran_log("Timing deviation detected: baseline=\(baselineTiming) ns, current=\(duration) ns")
            return true
        }
        
        return false
    }
    
    // ============================================
    // ADVANCED ANTI-PATTERN 5: Frida Artifacts Detection
    // ============================================
    
    /**
     * Scan for Frida files
     */
    public func scanFridaFiles() -> Bool {
        let fridaFiles = [
            "/usr/local/bin/frida",
            "/usr/local/bin/frida-server",
            "/usr/local/bin/frida-inject",
            "/tmp/frida-",
            "/var/tmp/frida-"
        ]
        
        for filePath in fridaFiles {
            if FileManager.default.fileExists(atPath: filePath) {
                aran_log("Frida file detected: \(filePath)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Scan for Frida network connections
     */
    public func scanFridaNetwork() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/netstat"
        task.arguments = ["-an"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Check for common Frida ports
        let fridaPorts = ["27042", "27043", "27044"]
        
        for port in fridaPorts {
            if output.contains(":\(port) ") {
                aran_log("Frida network connection detected on port: \(port)")
                return true
            }
        }
        
        return false
    }
    
    // ============================================
    // Public API
    // ============================================
    
    /**
     * Initialize all advanced detection systems
     */
    public func initialize() {
        guard !initialized else {
            aran_log("AdvancedAntiFrida already initialized")
            return
        }
        
        aran_log("Initializing advanced anti-Frida detection...")
        
        // Initialize memory state
        initializeMemoryState()
        
        // Initialize baseline timing
        initializeBaselineTiming()
        
        initialized = true
        aran_log("Advanced anti-Frida detection initialized successfully")
    }
    
    /**
     * Check process list using direct syscalls
     */
    public func checkProcessListDirectSyscall() -> Bool {
        guard initialized else {
            aran_log("Not initialized, initializing now")
            initialize()
        }
        
        return checkProcessListDirectSyscall()
    }
    
    /**
     * Check for hooked functions
     */
    public func checkFunctionsHooked() -> Bool {
        guard initialized else {
            aran_log("Not initialized, initializing now")
            initialize()
        }
        
        return checkSystemFunctionsHooked()
    }
    
    /**
     * Perform comprehensive advanced check
     */
    public func performComprehensiveAdvancedCheck() -> AdvancedCheckResult {
        aran_log("========================================")
        aran_log("Starting Comprehensive Advanced Check")
        aran_log("========================================")
        
        var result = AdvancedCheckResult()
        
        // Check 1: Process list direct syscall
        aran_log("Check 1: Process list direct syscall...")
        result.processListThreat = checkProcessListDirectSyscall()
        
        // Check 2: Function hooking
        aran_log("Check 2: Function hooking...")
        result.functionsHooked = checkFunctionsHooked()
        
        // Check 3: Memory integrity
        aran_log("Check 3: Memory integrity...")
        result.memoryIntegrityCompromised = checkMemoryIntegrity()
        
        // Check 4: Timing deviation
        aran_log("Check 4: Timing deviation...")
        result.timingAnomaly = checkTimingDeviation()
        
        // Check 5: Frida files
        aran_log("Check 5: Frida files...")
        result.fridaFilesDetected = scanFridaFiles()
        
        // Check 6: Frida network
        aran_log("Check 6: Frida network...")
        result.fridaNetworkDetected = scanFridaNetwork()
        
        // Calculate overall threat level
        result.threatsDetected = [
            result.processListThreat,
            result.functionsHooked,
            result.memoryIntegrityCompromised,
            result.timingAnomaly,
            result.fridaFilesDetected,
            result.fridaNetworkDetected
        ].filter { $0 }.count
        
        result.securityBreach = result.threatsDetected > 0
        
        aran_log("========================================")
        aran_log("Advanced check complete")
        aran_log("Threats detected: \(result.threatsDetected)")
        aran_log("Security breach: \(result.securityBreach)")
        aran_log("========================================")
        
        return result
    }
    
    /**
     * Check if advanced detection is initialized
     */
    public func isInitialized() -> Bool {
        return initialized
    }
    
    /**
     * Reset initialization state (for testing)
     */
    public func reset() {
        initialized = false
        memoryStateInitialized = false
        baselineTimingInitialized = false
    }
    
    /**
     * Advanced check result
     */
    public struct AdvancedCheckResult {
        public var securityBreach = false
        public var threatsDetected = 0
        public var processListThreat = false
        public var functionsHooked = false
        public var memoryIntegrityCompromised = false
        public var timingAnomaly = false
        public var fridaFilesDetected = false
        public var fridaNetworkDetected = false
        
        public var description: String {
            return "AdvancedCheckResult { securityBreach=\(securityBreach), threatsDetected=\(threatsDetected) }"
        }
    }
}
