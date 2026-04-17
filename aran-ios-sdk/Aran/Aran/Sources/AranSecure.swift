// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import UIKit
import CryptoKit

// MARK: - Threat Response

@objc public enum ThreatAction: Int {
    case warning = 0
    case block = 1
    case none = 2
    
    public var stringValue: String {
        switch self {
        case .warning: return "Warning"
        case .block: return "Block"
        case .none: return "None"
        }
    }
}

@objc public class AranThreat: NSObject {
    @objc public let threatCode: String
    @objc public let threatTitle: String
    @objc public let threatMessage: String
    @objc public let actionRequired: ThreatAction
    @objc public let status: String
    @objc public let statusDescription: String
    @objc public var isSkipped: Bool
    
    @objc public init(code: String, title: String, message: String,
                      action: ThreatAction, status: String = "detected",
                      statusDescription: String = "") {
        self.threatCode = code
        self.threatTitle = title
        self.threatMessage = message
        self.actionRequired = action
        self.status = status
        self.statusDescription = statusDescription
        self.isSkipped = false
    }
    
    @objc public func toDictionary() -> [String: Any] {
        return [
            "threatCode": threatCode,
            "threatTitle": threatTitle,
            "threatMessage": threatMessage,
            "actionRequired": actionRequired.stringValue,
            "status": status,
            "statusDescription": statusDescription,
            "isSkipped": isSkipped
        ]
    }
}

// MARK: - Security Threat Enum

@objc public enum AranSecurityThreat: Int, CaseIterable {
    case jailbreak = 0
    case debugger = 1
    case frida = 2
    case hooking = 3
    case runtimeManipulation = 4
    case tampering = 5
    case emulator = 6
    case vpn = 7
    case screenRecording = 8
    case screenshot = 9
    case remoteAccess = 10
    case smsForwarder = 11
    case proxy = 12
    case passcodeNotSet = 13
    case missingSecureEnclave = 14
    case deviceChange = 15
    case unofficialStore = 16
    case screenMirroring = 17
    case timeSpoofing = 18
    case locationSpoofing = 19
    case unsecureWifi = 20
    
    public var stringValue: String {
        switch self {
        case .jailbreak: return "jailbreak"
        case .debugger: return "debugger"
        case .frida: return "frida"
        case .hooking: return "hooking"
        case .runtimeManipulation: return "runtimeManipulation"
        case .tampering: return "tampering"
        case .emulator: return "emulator"
        case .vpn: return "vpn"
        case .screenRecording: return "screenRecording"
        case .screenshot: return "screenshot"
        case .remoteAccess: return "remoteAccess"
        case .smsForwarder: return "smsForwarder"
        case .proxy: return "proxy"
        case .passcodeNotSet: return "passcodeNotSet"
        case .missingSecureEnclave: return "missingSecureEnclave"
        case .deviceChange: return "deviceChange"
        case .unofficialStore: return "unofficialStore"
        case .screenMirroring: return "screenMirroring"
        case .timeSpoofing: return "timeSpoofing"
        case .locationSpoofing: return "locationSpoofing"
        case .unsecureWifi: return "unsecureWifi"
        }
    }
}

// MARK: - Screen Capture Status

@objc public enum AranScreenCaptureStatus: Int {
    case allowed = 0
    case blocked = 1
}

// MARK: - Main SDK Entry Point

@objc public class AranSecure: NSObject {
    
    @objc public static let shared = AranSecure()
    @objc public static let sdkVersion = "1.0.0"
    @objc public static let threatDetectedNotification = Notification.Name("AranThreatDetected")
    
    private var licenseKey: String?
    private var environment: AranEnvironment = .release
    private var expectedSignature: String?
    private weak var threatListener: AranThreatListener?
    private var reactionPolicy: ReactionPolicy = .logOnly
    private var isInitialized = false
    private var currentStatus: DeviceStatus?
    
    // Threat management
    private var detectedThreats: [AranThreat] = []
    private var skippedThreatCodes: Set<String> = []
    private var isAlertPresented = false
    
    // Screen capture blocking
    private var secureTextField: UITextField?
    private var isScreenCaptureBlocked = false
    
    // External ID
    private var externalId: String?
    
    // Malicious app detection
    private var harmAppsDetected = false
    private var harmAppsConfig: [[String: Any]] = []
    
    private override init() {
        super.init()
    }
    
    // MARK: - SDK Initialization
    
    @objc public static func start(
        licenseKey: String,
        environment: AranEnvironment
    ) {
        shared.licenseKey = licenseKey
        shared.environment = environment
        
        // Step 1: Run initial native threat scan
        
        // Step 2: Load Genesis Anchor
        
        var genesis = aran_load_genesis_state()
        
        // Extract native reaction policy         if let genesisPolicy = ReactionPolicy(rawValue: Int(genesis.default_reaction_policy)) {
            shared.reactionPolicy = genesisPolicy
        } else {
            shared.reactionPolicy = .killApp // Secure default
        }
        
        // Extract expected signature         
        shared.expectedSignature = nil
        
        // Step 3: Initialize Sigil Engine with license key
        
        do {
            try AranSigilEngine.shared.initialize(licenseKey: licenseKey)
        } catch {
            #if DEBUG
            print("Aran: Failed to initialize Sigil Engine: \(error)")
            #endif
        }
        
        // Step 4: Register URLProtocol interceptor
        
        URLProtocol.registerClass(AranURLProtocol.self)
        
        // Step 5: Start Phantom Channel
        
        if #available(iOS 15.0, *) {
            AranPhantomSync.shared.start(licenseKey: licenseKey, genesisState: &genesis)
        }
        
        // Step 6: Wipe Genesis state         
        aran_wipe_genesis_state(&genesis)
        
        // Step 7: Setup lifecycle observers
        
        if #available(iOS 13.0, *) {
            NotificationCenter.default.addObserver(shared, selector: #selector(shared.willResignActive),
                                                   name: UIScene.willDeactivateNotification, object: nil)
            NotificationCenter.default.addObserver(shared, selector: #selector(shared.willEnterForeground),
                                                   name: UIScene.willEnterForegroundNotification, object: nil)
        } else {
            NotificationCenter.default.addObserver(shared, selector: #selector(shared.willResignActive),
                                                   name: UIApplication.willResignActiveNotification, object: nil)
            NotificationCenter.default.addObserver(shared, selector: #selector(shared.willEnterForeground),
                                                   name: UIApplication.willEnterForegroundNotification, object: nil)
        }
        
        // Step 8: Start continuous environmental scanning
        
        AranEnvironmentalScanner.shared.startContinuousScanning { [weak shared] status in
            shared?.currentStatus = status
            shared?.handleThreats(status: status)
        }
        
        shared.isInitialized = true
        
        // Step 9: Initial threat scan
        
        let initialStatus = shared.checkEnvironment()
        if initialStatus.hasThreat {
            shared.handleThreats(status: initialStatus)
        }
        
        #if DEBUG
        print("Aran: SDK v\(sdkVersion) initialized [\(environment.stringValue)]")
        #endif
    }
    
    // MARK: - Native Threat Listener Registration
    
    @objc public func setNativeThreatListener(_ listener: AranThreatListener) {
        self.threatListener = listener
    }
    
    // MARK: - Phantom Channel Integration
    
    internal func updateReactionPolicyFromPhantom(_ policy: ReactionPolicy) {
        self.reactionPolicy = policy
    }
    
    internal func invokeThreatListener(status: DeviceStatus, overridePolicy: ReactionPolicy) {
        threatListener?.onThreatDetected(status: status, reactionPolicy: overridePolicy)
        
        NotificationCenter.default.post(
            name: AranSecure.threatDetectedNotification,
            object: nil,
            userInfo: ["status": status, "policy": overridePolicy.rawValue]
        )
        
        if overridePolicy == .killApp || overridePolicy == .blockAndReport {
            AranScorchedEarth.shared.executeScorchedEarth(reason: "Phantom Channel policy override: \(overridePolicy.stringValue)")
        }
    }
    
    // MARK: - Environment Check
    
    @objc public func checkEnvironment() -> DeviceStatus {
        let status = AranRASP.shared.fullScan(expectedSignature: expectedSignature)
        
        currentStatus = status
        buildThreatList(from: status)
        return status
    }
    
    @objc public func getCurrentStatus() -> DeviceStatus {
        return currentStatus ?? checkEnvironment()
    }
    
    // MARK: - SDK Version
    
    @objc public static func getSDKVersion() -> String {
        return sdkVersion
    }
    
    // MARK: - Device Fingerprint
    
    @objc public func getDeviceFingerprint() -> String {
        return AranRASPEngine.shared.computeDeviceFingerprint()
    }
    
    // MARK: - Signature Generation
    
    @objc public func getSignature(_ uuid: String) -> String {
        do {
            return try AranSigilEngine.shared.generateSignature(uuid: uuid)
        } catch {
            #if DEBUG
            print("Aran: Failed to generate signature: \(error)")
            #endif
            return ""
        }
    }
    
    // MARK: - Sigil Generation
    
    @objc public func generateSigil() throws -> String {
        let status = getCurrentStatus()
        return try AranSigilEngine.shared.generateSigil(payloadHash: "manual", status: status)
    }
    
    // MARK: - Cryptogram Generation
    
    @objc public func getCryptogram(nonce: Data) -> Data? {
        do {
            return try AranSigilEngine.shared.generateCryptogram(nonce: nonce)
        } catch {
            #if DEBUG
            print("Aran: Failed to generate cryptogram: \(error)")
            #endif
            return nil
        }
    }
    
    // MARK: - Screenshot Prevention
    
    @objc public func preventScreenshot(window: UIWindow, enable: Bool) {
        DispatchQueue.main.async {
            if enable {
                let field = UITextField()
                field.isSecureTextEntry = true
                field.isUserInteractionEnabled = false
                field.tag = 9999
                window.addSubview(field)
                field.translatesAutoresizingMaskIntoConstraints = false
                NSLayoutConstraint.activate([
                    field.centerXAnchor.constraint(equalTo: window.centerXAnchor),
                    field.centerYAnchor.constraint(equalTo: window.centerYAnchor)
                ])
                window.layer.superlayer?.addSublayer(field.layer)
                field.layer.sublayers?.first?.addSublayer(window.layer)
                self.secureTextField = field
                self.isScreenCaptureBlocked = true
            } else {
                if let existing = window.viewWithTag(9999) {
                    existing.removeFromSuperview()
                }
                self.secureTextField = nil
                self.isScreenCaptureBlocked = false
            }
        }
    }
    
    // MARK: - Screen Capture Blocking
    
    @objc public func blockScreenCapture(enable: Bool, window: UIWindow) {
        preventScreenshot(window: window, enable: enable)
    }
    
    @objc public func isScreenCaptureBlockedInWindow(_ window: UIWindow) -> Bool {
        return window.viewWithTag(9999) != nil
    }
    
    // MARK: - Secure Window
    
    @objc public func enableSecureWindow() {
        DispatchQueue.main.async {
            guard let window = self.getKeyWindow() else { return }
            self.preventScreenshot(window: window, enable: true)
        }
    }
    
    @objc public func disableSecureWindow() {
        DispatchQueue.main.async {
            guard let window = self.getKeyWindow() else { return }
            self.preventScreenshot(window: window, enable: false)
        }
    }
    
    // MARK: - External ID
    
    @objc public func storeExternalId(_ externalId: String) {
        self.externalId = externalId
        UserDefaults.standard.set(externalId, forKey: "aran.external.id")
    }
    
    @objc public func getExternalId() -> String? {
        return externalId ?? UserDefaults.standard.string(forKey: "aran.external.id")
    }
    
    // MARK: - Customer Reference ID
    
    @objc public func updateCustomerReferenceId(_ refId: String, completion: @escaping (Bool) -> Void) {
        storeExternalId(refId)
        completion(true)
    }
    
    // MARK: - Network Details
    @objc public func getNetworkDetails() -> [String: Any] {
        var details: [String: Any] = [:]
        
        details["vpnActive"] = AranEnvironmentalScanner.shared.checkVPN()
        details["proxyDetected"] = AranRASPEngine.shared.checkProxyDetected()
        
        if let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
            details["proxySettings"] = proxySettings
        }
        
        return details
    }
    
    // MARK: - Threat Management
    
    @objc public func getAllScannedThreats() -> [[String: Any]] {
        return detectedThreats.map { $0.toDictionary() }
    }
    
    @objc public func getActiveThreats() -> [AranThreat] {
        return detectedThreats.filter { !$0.isSkipped }
    }
    
    @objc public func isHarmAppsDetected() -> Bool {
        let status = getCurrentStatus()
        return status.remoteAccessActive || status.smsForwarderActive
    }
    
    @objc public func getHarmAppsConfig() -> [[String: Any]] {
        return harmAppsConfig
    }
    
    @objc public func skipThreat(code: String, completion: @escaping (Bool) -> Void) {
        skippedThreatCodes.insert(code)
        if let threat = detectedThreats.first(where: { $0.threatCode == code }) {
            threat.isSkipped = true
        }
        completion(true)
    }
    
    @objc public func skipThreats(codes: [String], completion: @escaping (Bool) -> Void) {
        for code in codes {
            skippedThreatCodes.insert(code)
            if let threat = detectedThreats.first(where: { $0.threatCode == code }) {
                threat.isSkipped = true
            }
        }
        completion(true)
    }
    
    @objc public func getSkippedThreats() -> String {
        return skippedThreatCodes.joined(separator: "-")
    }
    
    // MARK: - Threat Identifiers
    
    @objc public func getThreatIdentifiers() -> [String: Int] {
        var identifiers: [String: Int] = [:]
        for threat in AranSecurityThreat.allCases {
            identifiers[threat.stringValue] = Int.random(in: 100_000..<999_999_999)
        }
        return identifiers
    }
    
    // MARK: - Detected Threats as SecurityThreat list
    
    @objc public func getDetectedThreats() -> [Int] {
        guard let status = currentStatus else { return [] }
        var threats: [Int] = []
        
        if status.isJailbroken { threats.append(AranSecurityThreat.jailbreak.rawValue) }
        if status.fridaDetected { threats.append(AranSecurityThreat.frida.rawValue) }
        if status.debuggerAttached { threats.append(AranSecurityThreat.debugger.rawValue) }
        if status.emulatorDetected { threats.append(AranSecurityThreat.emulator.rawValue) }
        if status.hooked { threats.append(AranSecurityThreat.hooking.rawValue) }
        if status.tampered { threats.append(AranSecurityThreat.tampering.rawValue) }
        if status.runtimeManipulation { threats.append(AranSecurityThreat.runtimeManipulation.rawValue) }
        if status.vpnActive { threats.append(AranSecurityThreat.vpn.rawValue) }
        if status.screenRecording { threats.append(AranSecurityThreat.screenRecording.rawValue) }
        if status.remoteAccessActive { threats.append(AranSecurityThreat.remoteAccess.rawValue) }
        if status.smsForwarderActive { threats.append(AranSecurityThreat.smsForwarder.rawValue) }
        if status.proxyDetected { threats.append(AranSecurityThreat.proxy.rawValue) }
        if status.screenshotDetected { threats.append(AranSecurityThreat.screenshot.rawValue) }
        if status.screenMirroring { threats.append(AranSecurityThreat.screenMirroring.rawValue) }
        if status.timeSpoofing { threats.append(AranSecurityThreat.timeSpoofing.rawValue) }
        if status.locationSpoofing { threats.append(AranSecurityThreat.locationSpoofing.rawValue) }
        if status.unsecureWifi { threats.append(AranSecurityThreat.unsecureWifi.rawValue) }
        if !status.passcodeSet { threats.append(AranSecurityThreat.passcodeNotSet.rawValue) }
        if !status.secureEnclaveAvailable { threats.append(AranSecurityThreat.missingSecureEnclave.rawValue) }
        if status.deviceChanged { threats.append(AranSecurityThreat.deviceChange.rawValue) }
        if status.unofficialStore { threats.append(AranSecurityThreat.unofficialStore.rawValue) }
        
        return threats
    }
    
    // MARK: - Private: Build Threat List     
    private func buildThreatList(: DeviceStatus) {
        detectedThreats.removeAll()
        
        if status.isJailbroken {
            detectedThreats.append(AranThreat(
                code: "1001", title: "Jailbreak Detected",
                message: "This device appears to be jailbroken, which may compromise security.",
                action: .block))
        }
        if status.fridaDetected {
            detectedThreats.append(AranThreat(
                code: "1002", title: "Frida Detected",
                message: "Dynamic instrumentation tool Frida has been detected.",
                action: .block))
        }
        if status.debuggerAttached {
            detectedThreats.append(AranThreat(
                code: "1003", title: "Debugger Attached",
                message: "A debugger is currently attached to this process.",
                action: .warning))
        }
        if status.emulatorDetected {
            detectedThreats.append(AranThreat(
                code: "1004", title: "Simulator Detected",
                message: "Application is running in a simulator environment.",
                action: .warning))
        }
        if status.hooked {
            detectedThreats.append(AranThreat(
                code: "1005", title: "Hooking Framework Detected",
                message: "A runtime hooking framework has been detected.",
                action: .block))
        }
        if status.tampered {
            detectedThreats.append(AranThreat(
                code: "1006", title: "App Tampering Detected",
                message: "The application binary has been modified.",
                action: .block))
        }
        if status.runtimeManipulation {
            detectedThreats.append(AranThreat(
                code: "1007", title: "Runtime Manipulation",
                message: "Runtime manipulation tools have been detected.",
                action: .block))
        }
        if status.vpnActive {
            detectedThreats.append(AranThreat(
                code: "2001", title: "VPN Active",
                message: "A VPN connection is currently active.",
                action: .warning))
        }
        if status.screenRecording {
            detectedThreats.append(AranThreat(
                code: "2002", title: "Screen Recording Active",
                message: "Screen recording or mirroring is active.",
                action: .warning))
        }
        if status.remoteAccessActive {
            detectedThreats.append(AranThreat(
                code: "2003", title: "Remote Access App Detected",
                message: "A remote access application has been detected.",
                action: .warning))
        }
        if status.smsForwarderActive {
            detectedThreats.append(AranThreat(
                code: "2004", title: "SMS Forwarder Detected",
                message: "An SMS forwarding application has been detected.",
                action: .warning))
        }
        if status.proxyDetected {
            detectedThreats.append(AranThreat(
                code: "2005", title: "Proxy Detected",
                message: "An HTTP/HTTPS proxy is configured on this device.",
                action: .warning))
        }
        if !status.passcodeSet {
            detectedThreats.append(AranThreat(
                code: "3001", title: "Passcode Not Set",
                message: "Device passcode/biometric lock is not configured.",
                action: .warning))
        }
        if !status.secureEnclaveAvailable {
            detectedThreats.append(AranThreat(
                code: "3002", title: "Missing Secure Enclave",
                message: "Secure Enclave is not available on this device.",
                action: .warning))
        }
        if status.deviceChanged {
            detectedThreats.append(AranThreat(
                code: "3003", title: "Device Change Detected",
                message: "The device identity has changed since last check.",
                action: .warning))
        }
        if status.unofficialStore {
            detectedThreats.append(AranThreat(
                code: "3004", title: "Unofficial Store",
                message: "The app was not installed ",
                action: .warning))
        }
        if status.screenMirroring {
            detectedThreats.append(AranThreat(
                code: "2006", title: "Screen Mirroring Active",
                message: "Screen mirroring or external display detected. Sensitive data may be visible.",
                action: .warning))
        }
        if status.timeSpoofing {
            detectedThreats.append(AranThreat(
                code: "3005", title: "Time Spoofing Detected",
                message: "Device time appears to have been tampered with.",
                action: .warning))
        }
        if status.locationSpoofing {
            detectedThreats.append(AranThreat(
                code: "3006", title: "Location Spoofing Detected",
                message: "Location spoofing tools have been detected on the device.",
                action: .warning))
        }
        if status.unsecureWifi {
            detectedThreats.append(AranThreat(
                code: "2007", title: "Unsecure WiFi",
                message: "Device is connected to an unsecured WiFi network.",
                action: .warning))
        }
        
        // Re-apply skips
        for threat in detectedThreats {
            if skippedThreatCodes.contains(threat.threatCode) {
                threat.isSkipped = true
            }
        }
        
        harmAppsDetected = status.remoteAccessActive || status.smsForwarderActive
    }
    
    // MARK: - Threat Handling
    
    private func handleThreats(status: DeviceStatus) {
        guard status.hasThreat else { return }
        
        // Post notification
        
        NotificationCenter.default.post(
            name: AranSecure.threatDetectedNotification,
            object: nil,
            userInfo: [
                "status": status.toDictionary(),
                "reactionPolicy": reactionPolicy.stringValue,
                "threats": getDetectedThreats()
            ]
        )
        
        // Delegate callback
        threatListener?.onThreatDetected(status: status, reactionPolicy: reactionPolicy)
        
        switch reactionPolicy {
        case .logOnly:
            #if DEBUG
            print("Aran: Threat detected - \(status.threatCount) threats")
            #endif
            logThreatDetails(status)
            
        case .warnUser:
            #if DEBUG
            print("Aran: Threat detected - \(status.threatCount) threats")
            #endif
            logThreatDetails(status)
            showWarningAlert(status)
            
        case .blockApi:
            #if DEBUG
            print("Aran: Threat detected - Blocking API calls")
            #endif
            logThreatDetails(status)
            
        case .killApp:
            logThreatDetails(status)
            reportThreatToBackend(status)
            AranScorchedEarth.shared.executeScorchedEarth(reason: "KILL_APP: \(status.threatCount) threats (mask=0x\(String(status.nativeThreatMask, radix: 16)))")
            
        case .blockAndReport:
            logThreatDetails(status)
            reportThreatToBackend(status)
            AranScorchedEarth.shared.executeScorchedEarth(reason: "BLOCK_AND_REPORT: \(status.threatCount) threats")
            
        case .custom:
            break
        }
    }
    
    private func logThreatDetails(_ status: DeviceStatus) {
        #if DEBUG
        print("Aran: [\(status.eventId)] Threat Details (\(status.threatCount) threats, mask=0x\(String(status.nativeThreatMask, radix: 16))):")
        if status.isJailbroken { print("  - Device is jailbroken") }
        if status.fridaDetected { print("  - Frida detected") }
        if status.debuggerAttached { print("  - Debugger attached") }
        if status.emulatorDetected { print("  - Emulator detected") }
        if status.hooked { print("  - Hooking framework detected") }
        if status.tampered { print("  - App tampering detected") }
        if status.runtimeManipulation { print("  - Runtime manipulation detected") }
        if status.vpnActive { print("  - VPN active") }
        if status.screenRecording { print("  - Screen recording active") }
        if status.remoteAccessActive { print("  - Remote access app detected") }
        if status.smsForwarderActive { print("  - SMS forwarder detected") }
        if status.proxyDetected { print("  - Proxy detected") }
        if status.screenshotDetected { print("  - Screenshot detected") }
        if status.screenMirroring { print("  - Screen mirroring active") }
        if status.timeSpoofing { print("  - Time spoofing detected") }
        if status.locationSpoofing { print("  - Location spoofing detected") }
        if status.unsecureWifi { print("  - Unsecure WiFi") }
        if !status.passcodeSet { print("  - Passcode not set") }
        if !status.secureEnclaveAvailable { print("  - Secure Enclave missing") }
        if status.deviceChanged { print("  - Device changed") }
        if status.unofficialStore { print("  - Unofficial store") }
        #endif
    }
    
    // MARK: - Alert Presentation
    
    private func showWarningAlert(_ status: DeviceStatus) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            guard !self.isAlertPresented else { return }
            
            guard let topVC = self.getTopViewController() else { return }
            
            let activeThreats = self.getActiveThreats()
            guard let firstThreat = activeThreats.first else { return }
            
            let alert = UIAlertController(
                title: firstThreat.threatTitle,
                message: firstThreat.threatMessage,
                preferredStyle: .alert
            )
            
            if firstThreat.actionRequired == .warning {
                alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in
                    self?.isAlertPresented = false
                    self?.skipThreat(code: firstThreat.threatCode) { _ in }
                    // Show next threat if any
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        if let nextStatus = self?.currentStatus {
                            self?.showWarningAlert(nextStatus)
                        }
                    }
                })
            }
            
            self.isAlertPresented = true
            
            if topVC is UIAlertController {
                topVC.dismiss(animated: false) {
                    self.getTopViewController()?.present(alert, animated: true)
                }
            } else {
                topVC.present(alert, animated: true)
            }
        }
    }
    
    // MARK: - Lifecycle
    
    @objc private func willResignActive() {
        if isAlertPresented {
            DispatchQueue.main.async {
                self.getTopViewController()?.dismiss(animated: true) {
                    self.isAlertPresented = false
                }
            }
        }
    }
    
    @objc private func willEnterForeground() {
        // Re-scan on foreground
        DispatchQueue.global(qos: .background).async {
            let status = self.checkEnvironment()
            if status.hasThreat {
                self.handleThreats(status: status)
            }
        }
    }
    
    // MARK: - Backend Reporting
    
    // PRODUCTION: Load / secure vault
    private static let masterAesKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private static let hmacSecretBase64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    
    private func reportThreatToBackend(_ status: DeviceStatus) {
        guard let licenseKey = licenseKey else { return }
        
        let endpoint = "https://api.aran.mazhai.org/api/v1/telemetry/ingest"
        guard let url = URL(string: endpoint) else { return }
        
        var payload = status.toDictionary()
        payload["sdkVersion"] = AranSecure.sdkVersion
        payload["environment"] = environment.stringValue
        if let extId = getExternalId() {
            payload["externalId"] = extId
        }
        
        guard let plaintextData = try? JSONSerialization.data(withJSONObject: payload),
              let plaintext = String(data: plaintextData, encoding: .utf8) else { return }
        
        let nonce = UUID().uuidString
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        
        guard let encrypted = encryptAndSign(plaintext: plaintext, nonce: nonce, timestamp: timestamp) else { return }
        
        let envelope: [String: Any] = [
            "encrypted_data": encrypted.encryptedData,
            "signature": encrypted.signature,
            "nonce": nonce,
            "timestamp": timestamp
        ]
        
        let hmacInput = "POST:\(endpoint):\(nonce):\(timestamp)"
        let requestSignature = computeHmac(data: hmacInput)
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(licenseKey, forHTTPHeaderField: "X-Aran-License-Key")
        request.setValue(nonce, forHTTPHeaderField: "X-Aran-Nonce")
        request.setValue(String(timestamp), forHTTPHeaderField: "X-Aran-Timestamp")
        request.setValue(requestSignature, forHTTPHeaderField: "X-Aran-Signature")
        request.httpBody = try? JSONSerialization.data(withJSONObject: envelope)
        
        URLSession.shared.dataTask(with: request) { _, _, error in
            #if DEBUG
            if let error = error {
                print("Aran: Failed to report threat: \(error)")
            } else {
                print("Aran: Threat reported successfully")
            }
            #endif
        }.resume()
    }
    
    private struct EncryptedPayload {
        let encryptedData: String
        let signature: String
    }
    
    private func encryptAndSign(plaintext: String, nonce: String, timestamp: Int64) -> EncryptedPayload? {
        guard let aesKeyData = Data(base64Encoded: AranSecure.masterAesKeyBase64),
              let hmacKeyData = Data(base64Encoded: AranSecure.hmacSecretBase64),
              let plaintextData = plaintext.data(using: .utf8) else { return nil }
        
        let aad = "\(nonce):\(timestamp)"
        guard let aadData = aad.data(using: .utf8) else { return nil }
        
        // AES-256-GCM encrypt
        var iv = Data(count: 12)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 12, $0.baseAddress!) }
        
        let symmetricKey = SymmetricKey(data: aesKeyData)
        guard let sealedBox = try? AES.GCM.seal(plaintextData, using: symmetricKey, nonce: AES.GCM.Nonce(data: iv), authenticating: aadData) else { return nil }
        
        // Combine IV + ciphertext + tag
        var combined = Data()
        combined.append(iv)
        combined.append(sealedBox.ciphertext)
        combined.append(sealedBox.tag)
        
        // HMAC-SHA256 over (combined + aad)
        let hmacKey = SymmetricKey(data: hmacKeyData)
        var hmacData = combined
        hmacData.append(aadData)
        let signature = HMAC<SHA256>.authenticationCode(for: hmacData, using: hmacKey)
        
        return EncryptedPayload(
            encryptedData: combined.base64EncodedString(),
            signature: Data(signature).base64EncodedString()
        )
    }
    
    private func computeHmac(data: String) -> String {
        guard let hmacKeyData = Data(base64Encoded: AranSecure.hmacSecretBase64),
              let inputData = data.data(using: .utf8) else { return "" }
        let hmacKey = SymmetricKey(data: hmacKeyData)
        let signature = HMAC<SHA256>.authenticationCode(for: inputData, using: hmacKey)
        return Data(signature).base64EncodedString()
    }
    
    // MARK: - UI Helpers
    
    private func getKeyWindow() -> UIWindow? {
        if #available(iOS 13.0, *) {
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap { $0.windows }
                .first(where: \.isKeyWindow)
        } else {
            return UIApplication.shared.keyWindow
        }
    }
    
    private func getTopViewController() -> UIViewController? {
        guard let rootVC = getKeyWindow()?.rootViewController else { return nil }
        return findTopViewController(from: rootVC)
    }
    
    private func findTopViewController(: UIViewController) -> UIViewController? {
        if let tab = vc as? UITabBarController {
            return findTopViewController(from: tab.selectedViewController ?? vc)
        } else if let nav = vc as? UINavigationController {
            return findTopViewController(from: nav.visibleViewController ?? vc)
        } else if let presented = vc.presentedViewController {
            return findTopViewController(from: presented)
        }
        return vc
    }
}
