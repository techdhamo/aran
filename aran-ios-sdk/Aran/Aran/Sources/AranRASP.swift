// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

import Foundation
import UIKit

/// Phase 5: Swift integration layer.
/// Bridges the low-level C engine (AranCore) and ObjC checker (AranObjcChecker)
/// to the high-level DeviceStatus / ReactionPolicy / AranThreatListener system.
internal class AranRASP {
    
    static let shared = AranRASP()
    
    private init() {}
    
    // MARK: - Low-Level C Engine Bridge
    
    /// Execute the full C-level scan and return bitmask.
    func nativeScanAll() -> UInt32 {
        return aran_scan_all()
    }
    
    /// Decode the C-level bitmask into individual threat booleans.
    func decodeThreatMask(_ mask: UInt32) -> NativeThreatResult {
        return NativeThreatResult(
            debuggerSysctl:       (mask & UInt32(ARAN_THREAT_DEBUGGER)) != 0,
            debuggerMachPorts:    (mask & UInt32(ARAN_THREAT_DEBUGGER_MACH)) != 0,
            jailbreakFilesystem:  (mask & UInt32(ARAN_THREAT_JAILBREAK_FS)) != 0,
            jailbreakSymlinks:    (mask & UInt32(ARAN_THREAT_JAILBREAK_SYMLINK)) != 0,
            jailbreakWrite:       (mask & UInt32(ARAN_THREAT_JAILBREAK_WRITE)) != 0,
            sandboxViolation:     (mask & UInt32(ARAN_THREAT_SANDBOX_VIOLATION)) != 0,
            fridaDyld:            (mask & UInt32(ARAN_THREAT_FRIDA_DYLD)) != 0,
            substrateDyld:        (mask & UInt32(ARAN_THREAT_SUBSTRATE_DYLD)) != 0,
            fridaPort:            (mask & UInt32(ARAN_THREAT_FRIDA_PORT)) != 0,
            dyldEnvironment:      (mask & UInt32(ARAN_THREAT_DYLD_ENVVAR)) != 0,
            ttyAttached:          (mask & UInt32(ARAN_THREAT_TTY_ATTACHED)) != 0,
            ppidSuspicious:       (mask & UInt32(ARAN_THREAT_PPID_SUSPICIOUS)) != 0,
            shadowCydia:          (mask & UInt32(ARAN_THREAT_SHADOW_CYDIA)) != 0
        )
    }
    
    // MARK: - ObjC Anti-Swizzle Bridge
    
    /// Check if any sensitive Foundation/UIKit class has been method-swizzled.
    func checkSwizzling() -> SwizzleResult {
        let urlSessionHooked = AranObjcChecker.isNSURLSessionHooked()
        let urlConnectionHooked = AranObjcChecker.isNSURLConnectionHooked()
        let uiAppHooked = AranObjcChecker.isUIApplicationHooked()
        let secTrustHooked = AranObjcChecker.isSecTrustHooked()
        let hookedMethods = AranObjcChecker.hookedMethods() as? [String] ?? []
        
        return SwizzleResult(
            urlSessionHooked: urlSessionHooked,
            urlConnectionHooked: urlConnectionHooked,
            uiApplicationHooked: uiAppHooked,
            secTrustHooked: secTrustHooked,
            hookedMethods: hookedMethods
        )
    }
    
    // MARK: - Notifications
    
    static let allChecksFinishedNotification = Notification.Name("AranAllChecksFinished")
    
    // MARK: - Combined Full Scan
    
    /// Run ALL checks (C-level + ObjC swizzle + Swift-level) and produce a DeviceStatus.
    func fullScan(expectedSignature: String? = nil) -> DeviceStatus {
        // 1. Native C scan
        let mask = nativeScanAll()
        let native = decodeThreatMask(mask)
        
        // 2. ObjC swizzle check
        let swizzle = checkSwizzling()
        
        // 3. Swift-level environmental checks
        let scanner = AranEnvironmentalScanner.shared
        let raspEngine = AranRASPEngine.shared
        
        let vpnActive = scanner.checkVPN()
        let screenRecording = scanner.checkScreenRecording()
        let remoteAccessActive = scanner.checkRemoteAccessApps()
        let smsForwarderActive = scanner.checkSMSForwarderApps()
        let proxyDetected = raspEngine.checkProxyDetected()
        let passcodeSet = raspEngine.checkPasscodeSet()
        let secureEnclaveAvailable = raspEngine.checkSecureEnclaveAvailable()
        let deviceChanged = raspEngine.checkDeviceChanged()
        let unofficialStore = raspEngine.checkUnofficialStore()
        let tampered = raspEngine.checkTampering(expectedSignature: expectedSignature)
        
        // Extended threat detections
        let screenMirroring = scanner.checkScreenMirroring()
        let timeSpoofing = raspEngine.checkTimeSpoofing()
        let locationSpoofing = raspEngine.checkLocationSpoofing()
        let unsecureWifi = scanner.checkUnsecureWifi()
        
        // Combine native + swift results
        let isJailbroken = native.jailbreakFilesystem || native.jailbreakSymlinks || native.jailbreakWrite || native.sandboxViolation || native.shadowCydia
        let fridaDetected = native.fridaDyld || native.fridaPort
        let debuggerAttached = native.debuggerSysctl || native.debuggerMachPorts
        let hooked = native.substrateDyld || native.dyldEnvironment || swizzle.anyHooked
        let runtimeManipulation = native.substrateDyld || native.dyldEnvironment ||
                                  swizzle.anyHooked || native.ttyAttached
        
        #if targetEnvironment(simulator)
        let emulatorDetected = true
        #else
        let emulatorDetected = false
        #endif
        
        let status = DeviceStatus(
            isJailbroken: isJailbroken,
            fridaDetected: fridaDetected,
            debuggerAttached: debuggerAttached,
            emulatorDetected: emulatorDetected,
            hooked: hooked,
            tampered: tampered,
            runtimeManipulation: runtimeManipulation,
            vpnActive: vpnActive,
            screenRecording: screenRecording,
            remoteAccessActive: remoteAccessActive,
            smsForwarderActive: smsForwarderActive,
            proxyDetected: proxyDetected,
            screenshotDetected: false,
            screenMirroring: screenMirroring,
            timeSpoofing: timeSpoofing,
            locationSpoofing: locationSpoofing,
            unsecureWifi: unsecureWifi,
            passcodeSet: passcodeSet,
            secureEnclaveAvailable: secureEnclaveAvailable,
            deviceChanged: deviceChanged,
            unofficialStore: unofficialStore,
            deviceFingerprint: raspEngine.computeDeviceFingerprint(),
            appId: Bundle.main.bundleIdentifier ?? "unknown",
            nativeThreatMask: mask
        )
        
        // Post allChecksFinished notification
        NotificationCenter.default.post(
            name: AranRASP.allChecksFinishedNotification,
            object: nil,
            userInfo: ["status": status.toDictionary(), "eventId": status.eventId]
        )
        
        return status
    }
    
    // MARK: - Threat Response
    
    /// Execute reaction policy for a given status.
    func executeReaction(status: DeviceStatus, policy: ReactionPolicy,
                         listener: AranThreatListener?) {
        guard status.hasThreat else { return }
        
        // Always notify listener
        listener?.onThreatDetected(status: status, reactionPolicy: policy)
        
        // Always post notification for hybrid/Cordova/React Native bridges
        NotificationCenter.default.post(
            name: AranSecure.threatDetectedNotification,
            object: nil,
            userInfo: [
                "status": status.toDictionary(),
                "reactionPolicy": policy.stringValue,
                "nativeMask": nativeScanAll()
            ]
        )
        
        switch policy {
        case .killApp, .blockAndReport:
            AranScorchedEarth.shared.executeScorchedEarth(reason: "AranRASP: \(policy.stringValue) with \(status.threatCount) threats")
        case .custom:
            break // Fully delegated to listener
        default:
            break
        }
    }
}

// MARK: - Result Types

struct NativeThreatResult {
    let debuggerSysctl: Bool
    let debuggerMachPorts: Bool
    let jailbreakFilesystem: Bool
    let jailbreakSymlinks: Bool
    let jailbreakWrite: Bool
    let sandboxViolation: Bool
    let fridaDyld: Bool
    let substrateDyld: Bool
    let fridaPort: Bool
    let dyldEnvironment: Bool
    let ttyAttached: Bool
    let ppidSuspicious: Bool
    let shadowCydia: Bool
    
    var anyDebugger: Bool { debuggerSysctl || debuggerMachPorts }
    var anyJailbreak: Bool { jailbreakFilesystem || jailbreakSymlinks || jailbreakWrite || sandboxViolation || shadowCydia }
    var anyFrida: Bool { fridaDyld || fridaPort }
    var anyHooking: Bool { substrateDyld || dyldEnvironment }
}

struct SwizzleResult {
    let urlSessionHooked: Bool
    let urlConnectionHooked: Bool
    let uiApplicationHooked: Bool
    let secTrustHooked: Bool
    let hookedMethods: [String]
    
    var anyHooked: Bool {
        urlSessionHooked || urlConnectionHooked || uiApplicationHooked || secTrustHooked
    }
}
