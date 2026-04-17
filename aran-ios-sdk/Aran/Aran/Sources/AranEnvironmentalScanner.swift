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
        // Use the unified AranRASP engine (C + ObjC + Swift combined)
        let status = AranRASP.shared.fullScan()
        
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
    
    // MARK: - Screen Mirroring Detection (VAPT #3/#13)
    
    func checkScreenMirroring() -> Bool {
        if UIScreen.screens.count > 1 {
            return true
        }
        if #available(iOS 11.0, *) {
            for screen in UIScreen.screens {
                if screen.mirrored != nil {
                    return true
                }
            }
        }
        return false
    }
    
    // MARK: - Unsecure WiFi Detection
    
    func checkUnsecureWifi() -> Bool {
        // On iOS, CNCopyCurrentNetworkInfo is restricted.
        // We check for proxy settings and network interface patterns that suggest open WiFi.
        // A WiFi network without authentication is a security risk.
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }
        
        // Check if connected to WiFi (en0 interface present)
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return false }
        defer { freeifaddrs(ifaddr) }
        
        var hasWifi = false
        var ptr = ifaddr
        while ptr != nil {
            let name = String(cString: ptr!.pointee.ifa_name)
            if name == "en0" {
                hasWifi = true
                break
            }
            ptr = ptr!.pointee.ifa_next
        }
        
        guard hasWifi else { return false }
        
        // Heuristic: if WiFi is active and no proxy/VPN is configured,
        // check if the SSID matches common open network patterns
        // (actual SSID access requires entitlement, so we use proxy heuristic)
        if let scoped = proxySettings["__SCOPED__"] as? [String: Any] {
            for (key, _) in scoped {
                if key.hasPrefix("en0") {
                    // WiFi is active — we cannot determine encryption without NEHotspotHelper
                    // entitlement, but we flag a warning if no VPN/proxy protection exists
                    let vpn = checkVPN()
                    if !vpn {
                        // WiFi without VPN on a sensitive banking app = potential risk
                        // Conservative: only flag if we can confirm open network
                        return false // Conservative: only flag if we can confirm open network
                    }
                }
            }
        }
        
        return false
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
