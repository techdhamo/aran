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

@objc public class DeviceStatus: NSObject, Codable {
    // RASP Core Checks
    public let isJailbroken: Bool
    public let fridaDetected: Bool
    public let debuggerAttached: Bool
    public let emulatorDetected: Bool
    public let hooked: Bool
    public let tampered: Bool
    public let runtimeManipulation: Bool
    
    // Environmental Checks
    public let vpnActive: Bool
    public let screenRecording: Bool
    public let remoteAccessActive: Bool
    public let smsForwarderActive: Bool
    public let proxyDetected: Bool
    public let screenshotDetected: Bool
    
    // Device Integrity 
    public let passcodeSet: Bool
    public let secureEnclaveAvailable: Bool
    public let deviceChanged: Bool
    public let unofficialStore: Bool
    
    // Device Info
    public let deviceFingerprint: String
    public let appId: String
    public let timestamp: TimeInterval
    
    public var hasThreat: Bool {
        return isJailbroken || fridaDetected || debuggerAttached ||
               emulatorDetected || hooked || tampered || runtimeManipulation ||
               vpnActive || screenRecording || remoteAccessActive ||
               smsForwarderActive || proxyDetected || screenshotDetected ||
               !passcodeSet || !secureEnclaveAvailable || deviceChanged || unofficialStore
    }
    
    public var threatCount: Int {
        var count = 0
        if isJailbroken { count += 1 }
        if fridaDetected { count += 1 }
        if debuggerAttached { count += 1 }
        if emulatorDetected { count += 1 }
        if hooked { count += 1 }
        if tampered { count += 1 }
        if runtimeManipulation { count += 1 }
        if vpnActive { count += 1 }
        if screenRecording { count += 1 }
        if remoteAccessActive { count += 1 }
        if smsForwarderActive { count += 1 }
        if proxyDetected { count += 1 }
        if screenshotDetected { count += 1 }
        if !passcodeSet { count += 1 }
        if !secureEnclaveAvailable { count += 1 }
        if deviceChanged { count += 1 }
        if unofficialStore { count += 1 }
        return count
    }
    
    public init(
        isJailbroken: Bool,
        fridaDetected: Bool,
        debuggerAttached: Bool,
        emulatorDetected: Bool,
        hooked: Bool,
        tampered: Bool,
        runtimeManipulation: Bool = false,
        vpnActive: Bool,
        screenRecording: Bool,
        remoteAccessActive: Bool,
        smsForwarderActive: Bool,
        proxyDetected: Bool = false,
        screenshotDetected: Bool = false,
        passcodeSet: Bool = true,
        secureEnclaveAvailable: Bool = true,
        deviceChanged: Bool = false,
        unofficialStore: Bool = false,
        deviceFingerprint: String,
        appId: String
    ) {
        self.isJailbroken = isJailbroken
        self.fridaDetected = fridaDetected
        self.debuggerAttached = debuggerAttached
        self.emulatorDetected = emulatorDetected
        self.hooked = hooked
        self.tampered = tampered
        self.runtimeManipulation = runtimeManipulation
        self.vpnActive = vpnActive
        self.screenRecording = screenRecording
        self.remoteAccessActive = remoteAccessActive
        self.smsForwarderActive = smsForwarderActive
        self.proxyDetected = proxyDetected
        self.screenshotDetected = screenshotDetected
        self.passcodeSet = passcodeSet
        self.secureEnclaveAvailable = secureEnclaveAvailable
        self.deviceChanged = deviceChanged
        self.unofficialStore = unofficialStore
        self.deviceFingerprint = deviceFingerprint
        self.appId = appId
        self.timestamp = Date().timeIntervalSince1970
    }
    
    public func toDictionary() -> [String: Any] {
        return [
            "isJailbroken": isJailbroken,
            "fridaDetected": fridaDetected,
            "debuggerAttached": debuggerAttached,
            "emulatorDetected": emulatorDetected,
            "hooked": hooked,
            "tampered": tampered,
            "runtimeManipulation": runtimeManipulation,
            "vpnActive": vpnActive,
            "screenRecording": screenRecording,
            "remoteAccessActive": remoteAccessActive,
            "smsForwarderActive": smsForwarderActive,
            "proxyDetected": proxyDetected,
            "screenshotDetected": screenshotDetected,
            "passcodeSet": passcodeSet,
            "secureEnclaveAvailable": secureEnclaveAvailable,
            "deviceChanged": deviceChanged,
            "unofficialStore": unofficialStore,
            "deviceFingerprint": deviceFingerprint,
            "appId": appId,
            "hasThreat": hasThreat,
            "threatCount": threatCount,
            "timestamp": timestamp
        ]
    }
}
