//
//  AranIntegrity.swift
//  Aran iOS SDK
//
//  Swift wrapper for the C integrity module.
//  Provides enum-based state reporting — never calls exit() or abort().
//  The UI should disable high-risk features when compromised.
//

import Foundation
import UIKit

// ── Public API: Device Integrity State ─────────────────────────────────────────

public enum DeviceIntegrity: UInt8 {
    case secure = 0
    case jailbroken = 1
    case debuggerAttached = 2
    case hooked = 4
    case compromised = 8
    
    /// Combined flag for any detected threat
    public var hasThreat: Bool {
        return self != .secure
    }
    
    /// Human-readable description
    public var description: String {
        switch self {
        case .secure:
            return "Secure"
        case .jailbroken:
            return "Jailbreak Detected"
        case .debuggerAttached:
            return "Debugger Attached"
        case .hooked:
            return "Hooking Framework Detected"
        case .compromised:
            return "Device Compromised"
        }
    }
}

// ── URL Scheme Check (Swift-level, declared in Info.plist) ───────────────────

public class AranIntegrityChecker {
    
    public static let shared = AranIntegrityChecker()
    
    private var currentState: DeviceIntegrity = .secure
    private var isEnvironmentSecure = true
    
    private init() {}
    
    // ── C function declarations (bridged from AranIntegrity.c) ───────────────────
    
    @discardableResult
    private func performIntegrityCheck() -> Int32 {
        // This will be linked to aran_perform_integrity_check() from AranIntegrity.c
        // For now, we implement Swift-native checks that mirror the C logic
        var state: Int32 = 0
        
        // Check jailbreak paths (Swift implementation of stat checks)
        if checkJailbreakPaths() {
            state |= 1  // ARAN_INTEGRITY_JAILBROKEN
        }
        
        // Check debugger (Swift implementation of sysctl P_TRACED)
        if checkDebugger() {
            state |= 2  // ARAN_INTEGRITY_DEBUGGER
        }
        
        // Check dyld hooks (Swift implementation of _dyld_get_image_name)
        if checkDyldHooks() {
            state |= 4  // ARAN_INTEGRITY_HOOKED
        }
        
        if state != 0 {
            state |= 8  // ARAN_INTEGRITY_COMPROMISED
        }
        
        return state
    }
    
    // ── Swift-native checks (mirrors C logic) ───────────────────────────────────
    
    private func checkJailbreakPaths() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/usr/sbin/sshd",
            "/private/var/lib/apt",
            "/bin/bash",
            "/usr/lib/frida",
            "/usr/lib/cycript",
            "/usr/lib/substitute"
        ]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check for writable system directories
        let writablePaths = [
            "/System/Library/LaunchDaemons",
            "/Applications"
        ]
        
        for path in writablePaths {
            if FileManager.default.isWritableFile(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private func checkDebugger() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        if result == 0 {
            // P_TRACED flag indicates debugger is attached
            return (info.kp_proc.p_flag & P_TRACED) != 0
        }
        return false
    }
    
    private func checkDyldHooks() -> Bool {
        let count = _dyld_image_count()
        
        for i in 0..<count {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                
                // Check for common hooking frameworks
                let hookingLibraries = [
                    "frida",
                    "cycript",
                    "substitute",
                    "substrate",
                    "FridaGadget",
                    "libhook"
                ]
                
                for lib in hookingLibraries {
                    if name.lowercased().contains(lib) {
                        return true
                    }
                }
            }
        }
        return false
    }
    
    // ── URL Scheme Check (cydia://) ─────────────────────────────────────────────
    
    private func checkCydiaScheme() -> Bool {
        guard let url = URL(string: "cydia://") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }
    
    // ── Public API: Perform full integrity check ────────────────────────────────
    
    public func checkIntegrity() -> DeviceIntegrity {
        let state = performIntegrityCheck()
        
        if state & 8 != 0 {
            currentState = .compromised
            isEnvironmentSecure = false
        } else if state & 4 != 0 {
            currentState = .hooked
            isEnvironmentSecure = false
        } else if state & 2 != 0 {
            currentState = .debuggerAttached
            isEnvironmentSecure = false
        } else if state & 1 != 0 {
            currentState = .jailbroken
            isEnvironmentSecure = false
        } else {
            currentState = .secure
            isEnvironmentSecure = true
        }
        
        // Also check cydia URL scheme
        if checkCydiaScheme() {
            currentState = .jailbroken
            isEnvironmentSecure = false
        }
        
        return currentState
    }
    
    // ── Public API: Get current state without re-checking ───────────────────────
    
    public var integrity: DeviceIntegrity {
        return currentState
    }
    
    public var environmentSecure: Bool {
        return isEnvironmentSecure
    }
    
    // ── Public API: Generate integrity header (cryptographic) ────────────────────
    
    public func generateIntegrityHeader() -> String {
        let state = currentState.rawValue
        let salt = "ARAN_INTEGRITY_SALT_2024_HARDCORE"
        let timestamp = Int(Date().timeIntervalSince1970)
        
        // Simple hash for demonstration — in production use CryptoKit
        let combined = "\(state)|\(salt)|\(timestamp)"
        let hash = combined.data(using: .utf8)?.base64EncodedString() ?? ""
        
        // If compromised, prepend a marker the backend will recognize
        if !isEnvironmentSecure {
            return "COMPROMISED:\(hash)"
        }
        return "SECURE:\(hash)"
    }
    
    // ── Public API: Recommended action based on state ────────────────────────────
    
    public enum RecommendedAction {
        case allowAll
        case disableHighRiskFeatures
        case showServiceUnavailable
        case terminateSession
    }
    
    public func recommendedAction() -> RecommendedAction {
        switch currentState {
        case .secure:
            return .allowAll
        case .debuggerAttached:
            return .disableHighRiskFeatures
        case .hooked:
            return .disableHighRiskFeatures
        case .jailbroken:
            return .showServiceUnavailable
        case .compromised:
            return .terminateSession
        }
    }
}
