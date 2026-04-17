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

// MARK: - Vulnerability Response 

@objc public enum VulnerabilityAction: Int {
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

@objc public class AranVulnerability: NSObject {
    @objc public let vulnerabilityCode: String
    @objc public let vulnerabilityTitle: String
    @objc public let vulnerabilityMessage: String
    @objc public let actionRequired: VulnerabilityAction
    @objc public let status: String
    @objc public let statusDescription: String
    @objc public var isSkipped: Bool
    
    @objc public init(code: String, title: String, message: String,
                      action: VulnerabilityAction, status: String = "detected",
                      statusDescription: String = "") {
        self.vulnerabilityCode = code
        self.vulnerabilityTitle = title
        self.vulnerabilityMessage = message
        self.actionRequired = action
        self.status = status
        self.statusDescription = statusDescription
        self.isSkipped = false
    }
    
    @objc public func toDictionary() -> [String: Any] {
        return [
            "vulnerabilityCode": vulnerabilityCode,
            "vulnerabilityTitle": vulnerabilityTitle,
            "vulnerabilityMessage": vulnerabilityMessage,
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
    
    // Vulnerability management 
    private var detectedVulnerabilities: [AranVulnerability] = []
    private var skippedVulnerabilityCodes: Set<String> = []
    private var isAlertPresented = false
    
    // Screen capture blocking 
    private var secureTextField: UITextField?
    private var isScreenCaptureBlocked = false
    
    // External ID 
    private var externalId: String?
    
    // Harm apps 
    private var harmAppsDetected = false
    private var harmAppsConfig: [[String: Any]] = []
    
    private override init() {
        super.init()
    }
    
    // MARK: - SDK Initialization
    
    @objc public static func start(
        licenseKey: String,
        environment: AranEnvironment,
        expectedSignature: String? = nil,
        reactionPolicy: ReactionPolicy = .logOnly,
        listener: AranThreatListener? = nil
    ) {
        shared.licenseKey = licenseKey
        shared.environment = environment
        shared.expectedSignature = expectedSignature
        shared.reactionPolicy = reactionPolicy
        shared.threatListener = listener
        
        do {
            try AranSigilEngine.shared.initialize(licenseKey: licenseKey)
        } catch {
            print("Aran: Failed to initialize Sigil Engine: \(error)")
        }
        
        URLProtocol.registerClass(AranURLProtocol.self)
        
        // Setup lifecycle observers 
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
        
        AranEnvironmentalScanner.shared.startContinuousScanning { [weak shared] status in
            shared?.currentStatus = status
            shared?.handleThreats(status: status)
        }
        
        shared.isInitialized = true
        
        let initialStatus = shared.checkEnvironment()
        if initialStatus.hasThreat {
            shared.handleThreats(status: initialStatus)
        }
        
        print("Aran: SDK v\(sdkVersion) initialized [\(environment.stringValue)]")
    }
    
    // MARK: - Environment Check
    
    @objc public func checkEnvironment() -> DeviceStatus {
        let raspEngine = AranRASPEngine.shared
        
        let isJailbroken = raspEngine.checkJailbreak()
        let (fridaDetected, hooked) = raspEngine.checkFridaAndHooking()
        let debuggerAttached = raspEngine.checkDebugger()
        let emulatorDetected = raspEngine.checkEmulator()
        let tampered = raspEngine.checkTampering(expectedSignature: expectedSignature)
        let runtimeManipulation = raspEngine.checkRuntimeManipulation()
        
        let scanner = AranEnvironmentalScanner.shared
        let vpnActive = scanner.checkVPN()
        let screenRecording = scanner.checkScreenRecording()
        let remoteAccessActive = scanner.checkRemoteAccessApps()
        let smsForwarderActive = scanner.checkSMSForwarderApps()
        
        let proxyDetected = raspEngine.checkProxyDetected()
        let passcodeSet = raspEngine.checkPasscodeSet()
        let secureEnclaveAvailable = raspEngine.checkSecureEnclaveAvailable()
        let deviceChanged = raspEngine.checkDeviceChanged()
        let unofficialStore = raspEngine.checkUnofficialStore()
        
        let deviceFingerprint = raspEngine.computeDeviceFingerprint()
        let appId = Bundle.main.bundleIdentifier ?? "unknown"
        
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
            passcodeSet: passcodeSet,
            secureEnclaveAvailable: secureEnclaveAvailable,
            deviceChanged: deviceChanged,
            unofficialStore: unofficialStore,
            deviceFingerprint: deviceFingerprint,
            appId: appId
        )
        
        currentStatus = status
        buildVulnerabilityList(from: status)
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
            print("Aran: Failed to generate signature: \(error)")
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
            print("Aran: Failed to generate cryptogram: \(error)")
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
    
    // MARK: - Secure Window (legacy API)
    
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
    
    // MARK: - Customer Ref ID  updateCustRefId)
    
    @objc public func updateCustomerReferenceId(_ refId: String, completion: @escaping (Bool) -> Void) {
        storeExternalId(refId)
        completion(true)
    }
    
    // MARK: - Network Details  getNetworkDetails)
    
    @objc public func getNetworkDetails() -> [String: Any] {
        var details: [String: Any] = [:]
        
        details["vpnActive"] = AranEnvironmentalScanner.shared.checkVPN()
        details["proxyDetected"] = AranRASPEngine.shared.checkProxyDetected()
        
        if let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
            details["proxySettings"] = proxySettings
        }
        
        return details
    }
    
    // MARK: - Vulnerability Management 
    
    @objc public func getAllScannedVulnerabilities() -> [[String: Any]] {
        return detectedVulnerabilities.map { $0.toDictionary() }
    }
    
    @objc public func getActiveVulnerabilities() -> [AranVulnerability] {
        return detectedVulnerabilities.filter { !$0.isSkipped }
    }
    
    @objc public func isHarmAppsDetected() -> Bool {
        let status = getCurrentStatus()
        return status.remoteAccessActive || status.smsForwarderActive
    }
    
    @objc public func getHarmAppsConfig() -> [[String: Any]] {
        return harmAppsConfig
    }
    
    @objc public func skipVulnerability(code: String, completion: @escaping (Bool) -> Void) {
        skippedVulnerabilityCodes.insert(code)
        if let vuln = detectedVulnerabilities.first(where: { $0.vulnerabilityCode == code }) {
            vuln.isSkipped = true
        }
        completion(true)
    }
    
    @objc public func skipVulnerabilities(codes: [String], completion: @escaping (Bool) -> Void) {
        for code in codes {
            skippedVulnerabilityCodes.insert(code)
            if let vuln = detectedVulnerabilities.first(where: { $0.vulnerabilityCode == code }) {
                vuln.isSkipped = true
            }
        }
        completion(true)
    }
    
    @objc public func getSkippedVulnerabilities() -> String {
        return skippedVulnerabilityCodes.joined(separator: "-")
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
        if status.debuggerAttached { threats.append(AranSecurityThreat.debugger.rawValue) }
        if status.fridaDetected { threats.append(AranSecurityThreat.frida.rawValue) }
        if status.hooked { threats.append(AranSecurityThreat.hooking.rawValue) }
        if status.runtimeManipulation { threats.append(AranSecurityThreat.runtimeManipulation.rawValue) }
        if status.tampered { threats.append(AranSecurityThreat.tampering.rawValue) }
        if status.emulatorDetected { threats.append(AranSecurityThreat.emulator.rawValue) }
        if status.vpnActive { threats.append(AranSecurityThreat.vpn.rawValue) }
        if status.screenRecording { threats.append(AranSecurityThreat.screenRecording.rawValue) }
        if status.screenshotDetected { threats.append(AranSecurityThreat.screenshot.rawValue) }
        if status.remoteAccessActive { threats.append(AranSecurityThreat.remoteAccess.rawValue) }
        if status.smsForwarderActive { threats.append(AranSecurityThreat.smsForwarder.rawValue) }
        if status.proxyDetected { threats.append(AranSecurityThreat.proxy.rawValue) }
        if !status.passcodeSet { threats.append(AranSecurityThreat.passcodeNotSet.rawValue) }
        if !status.secureEnclaveAvailable { threats.append(AranSecurityThreat.missingSecureEnclave.rawValue) }
        if status.deviceChanged { threats.append(AranSecurityThreat.deviceChange.rawValue) }
        if status.unofficialStore { threats.append(AranSecurityThreat.unofficialStore.rawValue) }
        
        return threats
    }
    
    // MARK: - Private: Build Vulnerability List from Status
    
    private func buildVulnerabilityList(from status: DeviceStatus) {
        detectedVulnerabilities.removeAll()
        
        if status.isJailbroken {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1001", title: "Jailbreak Detected",
                message: "This device appears to be jailbroken, which may compromise security.",
                action: .block))
        }
        if status.fridaDetected {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1002", title: "Frida Detected",
                message: "Dynamic instrumentation tool Frida has been detected.",
                action: .block))
        }
        if status.debuggerAttached {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1003", title: "Debugger Attached",
                message: "A debugger is currently attached to this process.",
                action: .warning))
        }
        if status.emulatorDetected {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1004", title: "Simulator Detected",
                message: "Application is running in a simulator environment.",
                action: .warning))
        }
        if status.hooked {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1005", title: "Hooking Framework Detected",
                message: "A runtime hooking framework has been detected.",
                action: .block))
        }
        if status.tampered {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1006", title: "App Tampering Detected",
                message: "The application binary has been modified.",
                action: .block))
        }
        if status.runtimeManipulation {
            detectedVulnerabilities.append(AranVulnerability(
                code: "1007", title: "Runtime Manipulation",
                message: "Runtime manipulation tools have been detected.",
                action: .block))
        }
        if status.vpnActive {
            detectedVulnerabilities.append(AranVulnerability(
                code: "2001", title: "VPN Active",
                message: "A VPN connection is currently active.",
                action: .warning))
        }
        if status.screenRecording {
            detectedVulnerabilities.append(AranVulnerability(
                code: "2002", title: "Screen Recording Active",
                message: "Screen recording or mirroring is active.",
                action: .warning))
        }
        if status.remoteAccessActive {
            detectedVulnerabilities.append(AranVulnerability(
                code: "2003", title: "Remote Access App Detected",
                message: "A remote access application has been detected.",
                action: .warning))
        }
        if status.smsForwarderActive {
            detectedVulnerabilities.append(AranVulnerability(
                code: "2004", title: "SMS Forwarder Detected",
                message: "An SMS forwarding application has been detected.",
                action: .warning))
        }
        if status.proxyDetected {
            detectedVulnerabilities.append(AranVulnerability(
                code: "2005", title: "Proxy Detected",
                message: "An HTTP/HTTPS proxy is configured on this device.",
                action: .warning))
        }
        if !status.passcodeSet {
            detectedVulnerabilities.append(AranVulnerability(
                code: "3001", title: "Passcode Not Set",
                message: "Device passcode/biometric lock is not configured.",
                action: .warning))
        }
        if !status.secureEnclaveAvailable {
            detectedVulnerabilities.append(AranVulnerability(
                code: "3002", title: "Missing Secure Enclave",
                message: "Secure Enclave is not available on this device.",
                action: .warning))
        }
        if status.deviceChanged {
            detectedVulnerabilities.append(AranVulnerability(
                code: "3003", title: "Device Change Detected",
                message: "The device identity has changed since last check.",
                action: .warning))
        }
        if status.unofficialStore {
            detectedVulnerabilities.append(AranVulnerability(
                code: "3004", title: "Unofficial Store",
                message: "The app was not installed from the official App Store.",
                action: .warning))
        }
        
        // Re-apply skips
        for vuln in detectedVulnerabilities {
            if skippedVulnerabilityCodes.contains(vuln.vulnerabilityCode) {
                vuln.isSkipped = true
            }
        }
        
        harmAppsDetected = status.remoteAccessActive || status.smsForwarderActive
    }
    
    // MARK: - Threat Handling
    
    private func handleThreats(status: DeviceStatus) {
        guard status.hasThreat else { return }
        
        // Post notification (hybrid bridge integration)
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
            print("Aran: Threat detected - \(status.threatCount) threats")
            logThreatDetails(status)
            
        case .warnUser:
            print("Aran: Threat detected - \(status.threatCount) threats")
            logThreatDetails(status)
            showWarningAlert(status)
            
        case .blockApi:
            print("Aran: Threat detected - Blocking API calls")
            logThreatDetails(status)
            
        case .killApp:
            print("Aran: Threat detected - Terminating application")
            logThreatDetails(status)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                exit(0)
            }
            
        case .blockAndReport:
            print("Aran: Threat detected - Blocking and reporting")
            logThreatDetails(status)
            reportThreatToBackend(status)
            
        case .custom:
            print("Aran: Threat detected - Custom handler")
        }
    }
    
    private func logThreatDetails(_ status: DeviceStatus) {
        print("Aran: Threat Details:")
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
        if !status.passcodeSet { print("  - Passcode not set") }
        if !status.secureEnclaveAvailable { print("  - Secure Enclave missing") }
        if status.deviceChanged { print("  - Device changed") }
        if status.unofficialStore { print("  - Unofficial store") }
    }
    
    // MARK: - Alert Presentation 
    
    private func showWarningAlert(_ status: DeviceStatus) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            guard !self.isAlertPresented else { return }
            
            guard let topVC = self.getTopViewController() else { return }
            
            let activeVulns = self.getActiveVulnerabilities()
            guard let firstVuln = activeVulns.first else { return }
            
            let alert = UIAlertController(
                title: firstVuln.vulnerabilityTitle,
                message: firstVuln.vulnerabilityMessage,
                preferredStyle: .alert
            )
            
            if firstVuln.actionRequired == .warning {
                alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in
                    self?.isAlertPresented = false
                    self?.skipVulnerability(code: firstVuln.vulnerabilityCode) { _ in }
                    // Show next vulnerability if any
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
    
    private func reportThreatToBackend(_ status: DeviceStatus) {
        guard let licenseKey = licenseKey else { return }
        
        let endpoint = "https://api.aran.mazhai.org/v1/threats/report"
        guard let url = URL(string: endpoint) else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(licenseKey, forHTTPHeaderField: "X-Aran-License-Key")
        
        var payload = status.toDictionary()
        payload["sdkVersion"] = AranSecure.sdkVersion
        payload["environment"] = environment.stringValue
        if let extId = getExternalId() {
            payload["externalId"] = extId
        }
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        
        URLSession.shared.dataTask(with: request) { _, _, error in
            if let error = error {
                print("Aran: Failed to report threat: \(error)")
            } else {
                print("Aran: Threat reported successfully")
            }
        }.resume()
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
    
    private func findTopViewController(from vc: UIViewController) -> UIViewController? {
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
