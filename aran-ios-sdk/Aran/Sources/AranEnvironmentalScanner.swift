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
import SystemConfiguration
import SystemConfiguration.CaptiveNetwork

internal class AranEnvironmentalScanner {
    
    static let shared = AranEnvironmentalScanner()
    
    private var scanTimer: Timer?
    private var onThreatDetected: ((DeviceStatus) -> Void)?
    private var screenshotDetected = false
    private var screenshotObserverToken: NSObjectProtocol?
    
    private let remoteAccessSchemes = [
        "teamviewer://", "anydesk://", "chrome-remote-desktop://",
        "splashtop://", "logmein://", "gotomypc://",
        "vnc://", "rdp://", "teamviewerqs://", "anydeskremote://"
    ]
    
    private let smsForwarderSchemes = [
        "mysms://", "pushbullet://", "airdroid://",
        "mightytext://", "textra://", "pulse://",
        "messages://", "textfree://", "textnow://", "textplus://"
    ]
    
    private init() {
        setupScreenshotObserver()
    }
    
    deinit {
        if let token = screenshotObserverToken {
            NotificationCenter.default.removeObserver(token)
        }
    }
    
    // MARK: - Screenshot Observer 
    
    private func setupScreenshotObserver() {
        screenshotObserverToken = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.screenshotDetected = true
            // Reset after 10 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 10.0) {
                self?.screenshotDetected = false
            }
        }
    }
    
    // MARK: - Continuous Scanning
    
    func startContinuousScanning(interval: TimeInterval = 5.0, onThreat: @escaping (DeviceStatus) -> Void) {
        self.onThreatDetected = onThreat
        
        scanTimer?.invalidate()
        scanTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            DispatchQueue.global(qos: .background).async {
                self?.performScan()
            }
        }
        scanTimer?.fire()
    }
    
    func stopScanning() {
        scanTimer?.invalidate()
        scanTimer = nil
    }
    
    private func performScan() {
        let vpnActive = checkVPN()
        let screenRecording = checkScreenRecording()
        let remoteAccessActive = checkRemoteAccessApps()
        let smsForwarderActive = checkSMSForwarderApps()
        
        let raspEngine = AranRASPEngine.shared
        let isJailbroken = raspEngine.checkJailbreak()
        let (fridaDetected, hooked) = raspEngine.checkFridaAndHooking()
        let debuggerAttached = raspEngine.checkDebugger()
        let emulatorDetected = raspEngine.checkEmulator()
        let runtimeManipulation = raspEngine.checkRuntimeManipulation()
        let proxyDetected = raspEngine.checkProxyDetected()
        let passcodeSet = raspEngine.checkPasscodeSet()
        let secureEnclaveAvailable = raspEngine.checkSecureEnclaveAvailable()
        let deviceChanged = raspEngine.checkDeviceChanged()
        let unofficialStore = raspEngine.checkUnofficialStore()
        
        let status = DeviceStatus(
            isJailbroken: isJailbroken,
            fridaDetected: fridaDetected,
            debuggerAttached: debuggerAttached,
            emulatorDetected: emulatorDetected,
            hooked: hooked,
            tampered: false,
            runtimeManipulation: runtimeManipulation,
            vpnActive: vpnActive,
            screenRecording: screenRecording,
            remoteAccessActive: remoteAccessActive,
            smsForwarderActive: smsForwarderActive,
            proxyDetected: proxyDetected,
            screenshotDetected: screenshotDetected,
            passcodeSet: passcodeSet,
            secureEnclaveAvailable: secureEnclaveAvailable,
            deviceChanged: deviceChanged,
            unofficialStore: unofficialStore,
            deviceFingerprint: raspEngine.computeDeviceFingerprint(),
            appId: Bundle.main.bundleIdentifier ?? "unknown"
        )
        
        if status.hasThreat {
            DispatchQueue.main.async {
                self.onThreatDetected?(status)
            }
        }
    }
    
    // MARK: - VPN Detection
    
    func checkVPN() -> Bool {
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }
        
        let keys = proxySettings.keys
        for key in keys {
            let lowercaseKey = key.lowercased()
            if lowercaseKey.contains("tap") || lowercaseKey.contains("tun") ||
               lowercaseKey.contains("ipsec") || lowercaseKey.contains("ppp") {
                return true
            }
        }
        
        // Also check network interfaces
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return false }
        defer { freeifaddrs(ifaddr) }
        
        var ptr = ifaddr
        while ptr != nil {
            let name = String(cString: ptr!.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp") {
                return true
            }
            ptr = ptr!.pointee.ifa_next
        }
        
        return false
    }
    
    // MARK: - Screen Recording Detection 
    
    func checkScreenRecording() -> Bool {
        if #available(iOS 11.0, *) {
            if UIScreen.main.isCaptured {
                return true
            }
            for screen in UIScreen.screens {
                if screen.isCaptured {
                    return true
                }
            }
        }
        return false
    }
    
    // MARK: - Remote Access Apps Detection (thread-safe)
    
    func checkRemoteAccessApps() -> Bool {
        return checkURLSchemes(remoteAccessSchemes)
    }
    
    // MARK: - SMS Forwarder Apps Detection (thread-safe)
    
    func checkSMSForwarderApps() -> Bool {
        return checkURLSchemes(smsForwarderSchemes)
    }
    
    // MARK: - Thread-safe URL Scheme Check
    
    private func checkURLSchemes(_ schemes: [String]) -> Bool {
        var detected = false
        
        if Thread.isMainThread {
            for scheme in schemes {
                if let url = URL(string: scheme) {
                    if UIApplication.shared.canOpenURL(url) {
                        detected = true
                        break
                    }
                }
            }
        } else {
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                for scheme in schemes {
                    if let url = URL(string: scheme) {
                        if UIApplication.shared.canOpenURL(url) {
                            detected = true
                            break
                        }
                    }
                }
                semaphore.signal()
            }
            semaphore.wait()
        }
        
        return detected
    }
}
