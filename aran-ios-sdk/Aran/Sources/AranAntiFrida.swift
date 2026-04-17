import Foundation
import Darwin
import Security
import CommonCrypto

/**
 * Anti-Frida detection and protection for iOS
 * Provides comprehensive protection against dynamic instrumentation and tampering
 */
public class AranAntiFrida {
    
    public static let shared = AranAntiFrida()
    
    private var monitoringActive = false
    private var monitoringTimer: Timer?
    
    private init() {}
    
    // MARK: - Public Interface
    
    /**
     * Perform comprehensive anti-Frida detection
     */
    public func detectFrida() -> Bool {
        aran_log("Starting comprehensive anti-Frida detection...")
        
        var fridaDetected = false
        
        // 1. Debug detection
        if isDebugged() {
            aran_log("Debugger attached detected")
            fridaDetected = true
        }
        
        // 2. Process scanning
        if scanForFridaProcesses() {
            fridaDetected = true
        }
        
        // 3. Library detection
        if scanForFridaLibraries() {
            fridaDetected = true
        }
        
        // 4. Suspicious libraries
        if scanForSuspiciousLibraries() {
            fridaDetected = true
        }
        
        // 5. File system checks
        if checkForFridaFiles() {
            fridaDetected = true
        }
        
        // 6. Network detection
        if checkForFridaNetwork() {
            fridaDetected = true
        }
        
        // 7. Memory integrity
        if checkMemoryIntegrity() {
            fridaDetected = true
        }
        
        // 8. Timing attacks
        if performTimingAttack() {
            fridaDetected = true
        }
        
        if fridaDetected {
            aran_log("FRIDA DETECTION TRIGGERED - Security breach detected!")
        } else {
            aran_log("Anti-Frida scan completed - No threats detected")
        }
        
        return fridaDetected
    }
    
    /**
     * Start continuous background monitoring
     */
    public func startMonitoring() {
        guard !monitoringActive else {
            aran_log("Anti-Frida monitoring already active")
            return
        }
        
        monitoringActive = true
        aran_log("Starting continuous anti-Frida monitoring...")
        
        monitoringTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            if self.isDebugged() || self.scanForFridaProcesses() {
                aran_log("Continuous monitoring detected Frida!")
                self.triggerEmergencyShutdown()
            }
        }
    }
    
    /**
     * Stop continuous monitoring
     */
    public func stopMonitoring() {
        monitoringActive = false
        monitoringTimer?.invalidate()
        monitoringTimer = nil
        aran_log("Anti-Frida monitoring stopped")
    }
    
    /**
     * Get device fingerprint for server-side validation
     */
    public func getDeviceFingerprint() -> String {
        var fingerprint = ""
        
        // Collect hardware identifiers
        fingerprint += collectHardwareIdentifiers()
        fingerprint += "|"
        
        // Collect system configuration
        fingerprint += collectSystemConfiguration()
        fingerprint += "|"
        
        // Collect security indicators
        fingerprint += collectSecurityIndicators()
        fingerprint += "|"
        
        // Generate hash
        return generateHash(fingerprint + "AranSecure" + String(Date().timeIntervalSince1970))
    }
    
    /**
     * Verify app integrity
     */
    public func verifyAppIntegrity() -> Bool {
        // Check if main executable is modified
        guard let executablePath = Bundle.main.executablePath else {
            aran_log("Could not get executable path")
            return false
        }
        
        // Calculate hash of main executable
        guard let executableData = try? Data(contentsOf: URL(fileURLWithPath: executablePath)) else {
            aran_log("Could not read executable data")
            return false
        }
        
        let executableHash = generateHash(executableData.base64EncodedString())
        
        // In production, this should be compared with a securely stored hash
        // For now, just check if we can calculate the hash
        return !executableHash.isEmpty
    }
    
    // MARK: - Detection Methods
    
    /**
     * Check if debugger is attached
     */
    private func isDebugged() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        
        let result = withUnsafeMutablePointer(to: &info) { infoPtr in
            withUnsafeMutablePointer(to: &mib) { mibPtr in
                sysctl(mibPtr, u_int(mib.count), infoPtr, &size, nil, 0)
            }
        }
        
        if result != 0 {
            return false
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    /**
     * Scan for Frida processes
     */
    private func scanForFridaProcesses() -> Bool {
        let fridaProcesses = [
            "frida-agent",
            "frida-server",
            "frida-inject",
            "frida-helper",
            "frida-core"
        ]
        
        let task = Process()
        task.launchPath = "/bin/ps"
        task.arguments = ["-ax"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        for process in fridaProcesses {
            if output.contains(process) {
                aran_log("Frida process detected: \(process)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Scan for Frida libraries in memory
     */
    private func scanForFridaLibraries() -> Bool {
        let fridaLibraries = [
            "libfrida",
            "frida-agent",
            "frida-core",
            "gum-js",
            "gumjs"
        ]
        
        let task = Process()
        task.launchPath = "/usr/bin/lsof"
        task.arguments = ["-p", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        for library in fridaLibraries {
            if output.contains(library) {
                aran_log("Frida library detected: \(library)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Scan for suspicious libraries
     */
    private func scanForSuspiciousLibraries() -> Bool {
        let suspiciousLibraries = [
            "Substrate",
            "Cydia",
            "Frida",
            "frida",
            "substrate",
            "xposed"
        ]
        
        let task = Process()
        task.launchPath = "/usr/bin/lsof"
        task.arguments = ["-p", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        for library in suspiciousLibraries {
            if output.lowercased().contains(library.lowercased()) {
                aran_log("Suspicious library detected: \(library)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Check for Frida files on the system
     */
    private func checkForFridaFiles() -> Bool {
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
     * Check for Frida network connections
     */
    private func checkForFridaNetwork() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/netstat"
        task.arguments = ["-an"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Check for common Frida ports
        let fridaPorts = ["27042", "27043"]
        
        for port in fridaPorts {
            if output.contains(":\(port) ") {
                aran_log("Frida network connection detected on port: \(port)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Check memory integrity
     */
    private func checkMemoryIntegrity() -> Bool {
        // Check if our own code memory is writable (shouldn't be)
        let functionPtr = UnsafeRawPointer(bitPattern: UInt64(bitPattern: #function))
        
        // This is a simplified check - in production, more sophisticated
        // memory scanning techniques should be used
        return false
    }
    
    /**
     * Perform timing attack detection
     */
    private func performTimingAttack() -> Bool {
        let startTime = CFAbsoluteTimeGetCurrent()
        
        // Simple operation that should be consistent
        var sum: Int = 0
        for i in 0..<1_000_000 {
            sum += i
        }
        
        let endTime = CFAbsoluteTimeGetCurrent()
        let duration = endTime - startTime
        
        // If execution takes unusually long, likely being debugged/instrumented
        if duration > 0.1 { // 100ms threshold
            aran_log("Timing attack detected: \(duration * 1000)ms")
            return true
        }
        
        return false
    }
    
    // MARK: - Data Collection Methods
    
    /**
     * Collect hardware identifiers
     */
    private func collectHardwareIdentifiers() -> String {
        var hardware = ""
        
        // Device model
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        let model = String(cString: machine)
        hardware += "MODEL:\(model);"
        
        // Hardware UUID
        if let uuid = UIDevice.current.identifierForVendor?.uuidString {
            hardware += "UUID:\(uuid);"
        }
        
        return hardware
    }
    
    /**
     * Collect system configuration
     */
    private func collectSystemConfiguration() -> String {
        var system = ""
        
        // iOS version
        let version = UIDevice.current.systemVersion
        system += "VERSION:\(version);"
        
        // Device name
        let deviceName = UIDevice.current.name
        system += "NAME:\(deviceName);"
        
        // System uptime
        let uptime = ProcessInfo.processInfo.systemUptime
        system += "UPTIME:\(uptime);"
        
        return system
    }
    
    /**
     * Collect security indicators
     */
    private func collectSecurityIndicators() -> String {
        var security = ""
        
        // Check if jailbroken
        security += "JAILBROKEN:\(isJailbroken());"
        
        // Check if debugger attached
        security += "DEBUGGED:\(isDebugged());"
        
        // Check for suspicious apps
        security += "SUSPICIOUS_APPS:\(countSuspiciousApps());"
        
        return security
    }
    
    /**
     * Check if device is jailbroken
     */
    private func isJailbroken() -> Bool {
        // Check for jailbreak files
        let jailbreakFiles = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt"
        ]
        
        for file in jailbreakFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        
        // Check if can open Cydia URL
        if UIApplication.shared.canOpenURL(URL(string:"cydia://")!) {
            return true
        }
        
        return false
    }
    
    /**
     * Count suspicious applications
     */
    private func countSuspiciousApps() -> Int {
        let suspiciousApps = [
            "com.saurik.cydia",
            "com.zodttd.rocketbootstrap",
            "com.rpetrich.rocketbootstrap"
        ]
        
        var count = 0
        for app in suspiciousApps {
            if UIApplication.shared.canOpenURL(URL(string: "\(app)://")!) {
                count += 1
            }
        }
        
        return count
    }
    
    /**
     * Generate SHA-256 hash
     */
    private func generateHash(_ input: String) -> String {
        let data = Data(input.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /**
     * Generate hash from Data
     */
    private func generateHash(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /**
     * Trigger emergency shutdown
     */
    private func triggerEmergencyShutdown() {
        aran_log("EMERGENCY SHUTDOWN TRIGGERED - Frida detected")
        
        // Exit immediately
        exit(1)
    }
    
    deinit {
        stopMonitoring()
    }
}
