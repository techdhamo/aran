import Foundation
import os.log

// ============================================
// UNIVERSAL iOS RASP - Swift Extension
// BLACKBOX ARCHITECTURE - Static XCFramework
// Easy-to-use Swift interface for native iOS apps
// ============================================

/**
 * RASPCore Swift Extension
 * Provides a clean Swift API for native iOS applications
 * Internally calls the Objective-C++ bridge which calls the C++ core
 */
public extension RASPCore {
    
    /**
     * Security audit selector types
     */
    public enum AuditSelector: Int {
        case fullAudit = 0
        case jailbreakOnly = 1
        case debuggerOnly = 2
        case fridaOnly = 3
    }
    
    /**
     * Security status types
     */
    public enum StatusType: Int {
        case jailbreak = 0
        case debugger = 1
        case frida = 2
    }
    
    /**
     * Security result codes
     */
    public enum SecurityResult: Int {
        case securityOK = 0
        case suspicious = 1
        case highlySuspicious = 2
        case confirmedTamper = 3
    }
    
    /**
     * Perform security audit
     * - Parameter selector: Audit selector (default: fullAudit)
     * - Returns: Security result code
     */
    @objc public static func performAudit(selector: AuditSelector = .fullAudit) -> SecurityResult {
        let result = invokeAudit(selector.rawValue)
        return SecurityResult(rawValue: result) ?? .securityOK
    }
    
    /**
     * Get detection status
     * - Parameter statusType: Status type to check
     * - Returns: True if detected, false otherwise
     */
    @objc public static func getDetectionStatus(statusType: StatusType) -> Bool {
        let result = getStatus(statusType.rawValue)
        return result == 1
    }
    
    /**
     * Convenience method for full security audit
     * - Returns: Security result code
     */
    @objc public static func checkSecurity() -> SecurityResult {
        return performAudit(selector: .fullAudit)
    }
    
    /**
     * Convenience method for jailbreak detection
     * - Returns: True if jailbreak detected
     */
    @objc public static func isJailbroken() -> Bool {
        return getDetectionStatus(statusType: .jailbreak)
    }
    
    /**
     * Convenience method for debugger detection
     * - Returns: True if debugger detected
     */
    @objc public static func isDebuggerAttached() -> Bool {
        return getDetectionStatus(statusType: .debugger)
    }
    
    /**
     * Convenience method for Frida detection
     * - Returns: True if Frida detected
     */
    @objc public static func isFridaAttached() -> Bool {
        return getDetectionStatus(statusType: .frida)
    }
    
    /**
     * Get detailed security status
     * - Returns: Dictionary with all detection statuses
     */
    @objc public static func getDetailedStatus() -> [String: Any] {
        return [
            "jailbreakDetected": isJailbroken(),
            "debuggerDetected": isDebuggerAttached(),
            "fridaDetected": isFridaAttached(),
            "securityResult": checkSecurity().rawValue
        ]
    }
}

// ============================================
// SWIFT-ONLY INTERFACE (No Objective-C++ dependency)
// ============================================

/**
 * UniversalRASP - Pure Swift wrapper
 * Uses dlsym to dynamically load C++ functions
 * This is an alternative to the Objective-C++ bridge
 */
public class UniversalRASP {
    
    // Function pointer types
    private typealias AuditFunc = @convention(c) (Int32) -> Int32
    private typealias StatusFunc = @convention(c) (Int32) -> Int32
    
    private static var auditFunc: AuditFunc?
    private static var statusFunc: StatusFunc?
    private static var initialized = false
    
    /**
     * Initialize UniversalRASP
     * Dynamically loads C++ functions using dlsym
     */
    public static func initialize() {
        guard !initialized else { return }
        
        // Load functions using dlsym
        auditFunc = loadNativeFunction(name: "universal_rasp_execute_audit")
        statusFunc = loadNativeFunction(name: "universal_rasp_get_status")
        
        initialized = true
        os_log(.info, log: OSLog(subsystem: "com.aran.security", category: "AranRASP"), "UniversalRASP initialized")
    }
    
    /**
     * Dynamically load native function using dlsym
     */
    private static func loadNativeFunction<T>(name: String) -> T? {
        guard let handle = dlopen(nil, RTLD_NOW) else {
            os_log(.error, log: OSLog(subsystem: "com.aran.security", category: "AranRASP"), "Failed to load native library")
            return nil
        }
        
        guard let symbol = dlsym(handle, name) else {
            os_log(.error, log: OSLog(subsystem: "com.aran.security", category: "AranRASP"), "Failed to find symbol: %{public}@", name)
            dlclose(handle)
            return nil
        }
        
        return unsafeBitCast(symbol, to: T.self)
    }
    
    /**
     * Perform security audit
     * - Parameter selector: Audit selector
     * - Returns: Security result code
     */
    public static func performAudit(selector: Int = 0) -> Int {
        if !initialized {
            initialize()
        }
        
        guard let func = auditFunc else {
            os_log(.error, log: OSLog(subsystem: "com.aran.security", category: "AranRASP"), "Audit function not available")
            return -1
        }
        
        return Int(func(Int32(selector)))
    }
    
    /**
     * Get detection status
     * - Parameter statusType: Status type
     * - Returns: Detection status
     */
    public static func getStatus(statusType: Int) -> Bool {
        if !initialized {
            initialize()
        }
        
        guard let func = statusFunc else {
            os_log(.error, log: OSLog(subsystem: "com.aran.security", category: "AranRASP"), "Status function not available")
            return false
        }
        
        return Int(func(Int32(statusType))) == 1
    }
    
    /**
     * Convenience methods
     */
    public static func isJailbroken() -> Bool {
        return getStatus(statusType: 0)
    }
    
    public static func isDebuggerAttached() -> Bool {
        return getStatus(statusType: 1)
    }
    
    public static func isFridaAttached() -> Bool {
        return getStatus(statusType: 2)
    }
}
