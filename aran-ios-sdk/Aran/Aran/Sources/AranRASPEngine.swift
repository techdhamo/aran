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
import CommonCrypto
import CryptoKit
import LocalAuthentication
import Security
import MachO
import CoreLocation
import NetworkExtension

internal class AranRASPEngine {
    
    static let shared = AranRASPEngine()
    
    private var previousDeviceFingerprint: String?
    
    private init() {
        previousDeviceFingerprint = UserDefaults.standard.string(forKey: "aran.device.fingerprint")
    }
    
    // MARK: - Jailbreak Detection
    
    func checkJailbreak() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        let suspiciousFiles = [
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/bin/bash",
            "/bin/sh",
            "/usr/libexec/ssh-keysign",
            "/usr/bin/ssh",
            "/var/checkra1n.dmg",
            "/var/binpack"
        ]
        
        for path in suspiciousFiles {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        if canWriteToRestrictedPath() {
            return true
        }
        
        // Thread-safe Cydia URL check (UIApplication must be on main thread)
        var cydiaDetected = false
        if Thread.isMainThread {
            if let url = URL(string: "cydia://") {
                cydiaDetected = UIApplication.shared.canOpenURL(url)
            }
            if !cydiaDetected, let url = URL(string: "sileo://") {
                cydiaDetected = UIApplication.shared.canOpenURL(url)
            }
            if !cydiaDetected, let url = URL(string: "zbra://") {
                cydiaDetected = UIApplication.shared.canOpenURL(url)
            }
        } else {
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                if let url = URL(string: "cydia://") {
                    cydiaDetected = UIApplication.shared.canOpenURL(url)
                }
                if !cydiaDetected, let url = URL(string: "sileo://") {
                    cydiaDetected = UIApplication.shared.canOpenURL(url)
                }
                if !cydiaDetected, let url = URL(string: "zbra://") {
                    cydiaDetected = UIApplication.shared.canOpenURL(url)
                }
                semaphore.signal()
            }
            semaphore.wait()
        }
        
        if cydiaDetected {
            return true
        }
        
        // Check for symbolic links
        let symLinks = ["/Applications", "/Library/Ringtones", "/Library/Wallpaper",
                        "/usr/arm-apple-darwin9", "/usr/include", "/usr/libexec", "/usr/share"]
        for path in symLinks {
            var s = stat()
            if lstat(path, &s) == 0 {
                if (s.st_mode & S_IFLNK) == S_IFLNK {
                    return true
                }
            }
        }
        
        return false
        #endif
    }
    
    private func canWriteToRestrictedPath() -> Bool {
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    // MARK: - Frida & Hooking Detection (dlopen-based, replaces _dyld)
    
    func checkFridaAndHooking() -> (fridaDetected: Bool, hooked: Bool) {
        var fridaDetected = false
        var hooked = false
        
        // Check via dlopen for suspicious libraries
        let fridaLibs = ["FridaGadget", "frida-agent", "frida-gadget", "frida-core"]
        let hookingLibs = ["substrate", "Substrate", "CydiaSubstrate", "Substitute",
                           "libcycript", "SubstrateLoader", "SSLKillSwitch",
                           "SSLKillSwitch2", "MobileSubstrate", "TweakInject",
                           "libhooker", "A-Bypass", "FlyJB", "Liberty"]
        
        for lib in fridaLibs {
            if let handle = dlopen(lib, RTLD_NOLOAD) {
                dlclose(handle)
                fridaDetected = true
            }
        }
        
        for lib in hookingLibs {
            if let handle = dlopen(lib, RTLD_NOLOAD) {
                dlclose(handle)
                hooked = true
            }
        }
        
        // Check loaded images via dyld
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                let lower = name.lowercased()
                if lower.contains("frida") || lower.contains("fridagadget") {
                    fridaDetected = true
                }
                if lower.contains("substrate") || lower.contains("substitute") ||
                   lower.contains("cycript") || lower.contains("libhooker") ||
                   lower.contains("tweakinject") || lower.contains("sslkillswitch") {
                    hooked = true
                }
            }
        }
        
        // Check Frida server port (default 27042)
        if checkPort(27042) || checkPort(27043) {
            fridaDetected = true
        }
        
        return (fridaDetected, hooked)
    }
    
    // MARK: - Runtime Manipulation Detection
    
    func checkRuntimeManipulation() -> Bool {
        // Check for method swizzling indicators
        #if targetEnvironment(simulator)
        return false
        #else
        // Check if commonly hooked methods have been swizzled
        let suspiciousEnvVars = ["DYLD_INSERT_LIBRARIES", "_MSSafeMode", "DYLD_LIBRARY_PATH"]
        for envVar in suspiciousEnvVars {
            if let val = getenv(envVar), String(cString: val).count > 0 {
                return true
            }
        }
        
        // Check for Objective-C runtime manipulation
        if let handle = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOLOAD) {
            if dlsym(handle, "method_exchangeImplementations") != nil {
                // This is always present, but check if suspicious libs loaded it
                let imgCount = _dyld_image_count()
                for i in 0..<imgCount {
                    if let name = _dyld_get_image_name(i) {
                        let path = String(cString: name)
                        if path.contains("MobileSubstrate") || path.contains("TweakInject") ||
                           path.contains("libhooker") {
                            dlclose(handle)
                            return true
                        }
                    }
                }
            }
            dlclose(handle)
        }
        
        return false
        #endif
    }
    
    // MARK: - Debugger Detection
    
    func checkDebugger() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // MARK: - Emulator Detection
    
    func checkEmulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    // MARK: - App Tampering Detection
    
    func checkTampering(expectedSignature: String?) -> Bool {
        guard let expectedSignature = expectedSignature else {
            return false
        }
        
        guard let executablePath = Bundle.main.executablePath,
              let executableData = try? Data(contentsOf: URL(fileURLWithPath: executablePath)) else {
            return true
        }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        executableData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(executableData.count), &hash)
        }
        let actualSignature = hash.map { String(format: "%02x", $0) }.joined().uppercased()
        
        return actualSignature != expectedSignature.uppercased()
    }
    
    // MARK: - Passcode Detection
    
    func checkPasscodeSet() -> Bool {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        }
        
        // If biometry is not available, check if passcode at least is set
        if let err = error {
            // errSecAuthFailed = -25293, passcode not set
            if err.code == Int(kLAErrorPasscodeNotSet) {
                return false
            }
        }
        
        return true
    }
    
    // MARK: - Secure Enclave Detection
    
    func checkSecureEnclaveAvailable() -> Bool {
        if #available(iOS 13.0, *) {
            return SecureEnclave.isAvailable
        }
        // Fallback: try to create a Secure Enclave key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            _ = key // Successfully created, SE is available
            return true
        }
        return false
    }
    
    // MARK: - Unofficial Store Detection
    
    func checkUnofficialStore() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // Check App Store receipt
        guard let receiptURL = Bundle.main.appStoreReceiptURL else {
            return true
        }
        
        if !FileManager.default.fileExists(atPath: receiptURL.path) {
            return true
        }
        
        // Check if receipt path contains "sandboxReceipt" (TestFlight/dev builds)
        let receiptPath = receiptURL.path
        if receiptPath.contains("sandboxReceipt") {
            // TestFlight or development — not necessarily unofficial
            return false
        }
        
        return false
        #endif
    }
    
    // MARK: - Device Change Detection
    
    func checkDeviceChanged() -> Bool {
        let currentFingerprint = computeDeviceFingerprint()
        
        if let previous = previousDeviceFingerprint {
            if previous != currentFingerprint {
                // Update stored fingerprint
                UserDefaults.standard.set(currentFingerprint, forKey: "aran.device.fingerprint")
                previousDeviceFingerprint = currentFingerprint
                return true
            }
        } else {
            // First run, store fingerprint
            UserDefaults.standard.set(currentFingerprint, forKey: "aran.device.fingerprint")
            previousDeviceFingerprint = currentFingerprint
        }
        
        return false
    }
    
    // MARK: - Proxy Detection
    
    func checkProxyDetected() -> Bool {
        // Check HTTP proxy
        if let proxy = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
            if let httpProxy = proxy[kCFNetworkProxiesHTTPProxy as String] as? String,
               !httpProxy.isEmpty {
                return true
            }
            if let httpsProxy = proxy["HTTPSProxy"] as? String,
               !httpsProxy.isEmpty {
                return true
            }
            if let httpEnable = proxy[kCFNetworkProxiesHTTPEnable as String] as? Int,
               httpEnable == 1 {
                return true
            }
        }
        return false
    }
    
    // MARK: - Time Spoofing Detection
    
    func checkTimeSpoofing() -> Bool {
        // Compare system uptime-derived time with Date() to detect manual clock changes
        // If the device time has been set significantly ahead/behind, the delta will be abnormal
        let uptime = ProcessInfo.processInfo.systemUptime
        let bootTime = Date().timeIntervalSince1970 - uptime
        
        // Store last known boot time to detect jumps
        let storedBootTime = UserDefaults.standard.double(forKey: "aran.boottime")
        if storedBootTime > 0 {
            // Boot time should be relatively stable. A large jump (>300s) indicates time tampering
            let drift = abs(bootTime - storedBootTime)
            if drift > 300 {
                UserDefaults.standard.set(bootTime, forKey: "aran.boottime")
                return true
            }
        }
        UserDefaults.standard.set(bootTime, forKey: "aran.boottime")
        
        // Also check if automatic time is disabled (heuristic: compare with compile time)
        // If current date is before the build date, time is clearly spoofed
        let buildDateString = "2026-02-23"
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        if let buildDate = formatter.date(from: buildDateString) {
            if Date() < buildDate.addingTimeInterval(-86400) {
                return true
            }
        }
        
        return false
    }
    
    // MARK: - Location Spoofing Detection
    
    func checkLocationSpoofing() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // Check if location simulation is likely active
        // On jailbroken devices, mock location providers can be injected
        // Check for common location spoofing apps/dylibs
        let spoofingIndicators = [
            "/Applications/LocationFaker.app",
            "/Applications/LocationHandle.app",
            "/Applications/akLocationX.app",
            "/Library/MobileSubstrate/DynamicLibraries/LocationFaker.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LocationHandle.plist"
        ]
        
        for path in spoofingIndicators {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check loaded dylibs for location spoofing keywords
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName).lowercased()
                if name.contains("locationfaker") || name.contains("locationhandle") ||
                   name.contains("aklocationx") || name.contains("gpscheat") ||
                   name.contains("locationsimulator") {
                    return true
                }
            }
        }
        
        return false
        #endif
    }
    
    // MARK: - Screen Mirroring Detection (VAPT #3/#13)
    
    func checkScreenMirroring() -> Bool {
        // Check for external displays (AirPlay mirroring, wired mirroring)
        if UIScreen.screens.count > 1 {
            return true
        }
        
        // Check for AirPlay mirroring via UIScreen.mirrored
        if #available(iOS 11.0, *) {
            for screen in UIScreen.screens {
                if screen.mirrored != nil {
                    return true
                }
            }
        }
        
        return false
    }
    
    // MARK: - Helpers
    
    private func checkPort(_ port: Int32) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }
        
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        
        var timeout = timeval(tv_sec: 0, tv_usec: 100000) // 100ms
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        
        return result == 0
    }
    
    func computeDeviceFingerprint() -> String {
        var fingerprint = ""
        
        if let identifierForVendor = UIDevice.current.identifierForVendor?.uuidString {
            fingerprint += identifierForVendor
        }
        
        fingerprint += UIDevice.current.systemName
        fingerprint += UIDevice.current.systemVersion
        fingerprint += UIDevice.current.model
        fingerprint += UIDevice.current.name
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        if let data = fingerprint.data(using: .utf8) {
            data.withUnsafeBytes {
                _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
            }
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Data SHA256 Extension

extension Data {
    func sha256() -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash)
        }
        return Data(hash)
    }
}
