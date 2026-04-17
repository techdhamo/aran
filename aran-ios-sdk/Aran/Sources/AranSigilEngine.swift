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
import CryptoKit
import Security
import CommonCrypto

internal class AranSigilEngine {
    
    static let shared = AranSigilEngine()
    
    private var secureEnclaveKey: SecureEnclave.P256.Signing.PrivateKey?
    private var regularKey: P256.Signing.PrivateKey?
    private var licenseKey: String?
    
    private init() {}
    
    func initialize(licenseKey: String) throws {
        self.licenseKey = licenseKey
        
        if SecureEnclave.isAvailable {
            do {
                self.secureEnclaveKey = try SecureEnclave.P256.Signing.PrivateKey()
            } catch {
                self.regularKey = P256.Signing.PrivateKey()
            }
        } else {
            self.regularKey = P256.Signing.PrivateKey()
        }
    }
    
    // MARK: - JWT Sigil Generation
    
    func generateSigil(payloadHash: String, status: DeviceStatus) throws -> String {
        guard let licenseKey = self.licenseKey else {
            throw AranError.notInitialized
        }
        
        let header = [
            "alg": "ES256",
            "typ": "JWT",
            "kid": licenseKey
        ]
        
        let payload: [String: Any] = [
            "iss": "aran-security",
            "sub": status.appId,
            "iat": Int(Date().timeIntervalSince1970),
            "exp": Int(Date().timeIntervalSince1970) + 300,
            "jti": UUID().uuidString,
            "payloadHash": payloadHash,
            "deviceFingerprint": status.deviceFingerprint,
            "threatStatus": [
                "isJailbroken": status.isJailbroken,
                "fridaDetected": status.fridaDetected,
                "debuggerAttached": status.debuggerAttached,
                "emulatorDetected": status.emulatorDetected,
                "hooked": status.hooked,
                "tampered": status.tampered,
                "runtimeManipulation": status.runtimeManipulation,
                "vpnActive": status.vpnActive,
                "screenRecording": status.screenRecording,
                "proxyDetected": status.proxyDetected,
                "passcodeSet": status.passcodeSet,
                "secureEnclaveAvailable": status.secureEnclaveAvailable,
                "hasThreat": status.hasThreat,
                "threatCount": status.threatCount
            ]
        ]
        
        guard let headerData = try? JSONSerialization.data(withJSONObject: header),
              let payloadData = try? JSONSerialization.data(withJSONObject: payload) else {
            throw AranError.sigilGenerationFailed
        }
        
        let headerBase64 = headerData.base64URLEncodedString()
        let payloadBase64 = payloadData.base64URLEncodedString()
        
        let signingInput = "\(headerBase64).\(payloadBase64)"
        guard let signingData = signingInput.data(using: .utf8) else {
            throw AranError.sigilGenerationFailed
        }
        
        let signatureData: Data
        if let secureKey = secureEnclaveKey {
            let signature = try secureKey.signature(for: signingData)
            signatureData = signature.rawRepresentation
        } else if let regKey = regularKey {
            let signature = try regKey.signature(for: signingData)
            signatureData = signature.rawRepresentation
        } else {
            throw AranError.secureEnclaveUnavailable
        }
        
        let signatureBase64 = signatureData.base64URLEncodedString()
        return "\(signingInput).\(signatureBase64)"
    }
    
    func generateSigilForRequest(requestBody: Data?, status: DeviceStatus) throws -> String {
        let hash: String
        if let body = requestBody {
            let bodyHash = SHA256.hash(data: body)
            hash = bodyHash.compactMap { String(format: "%02x", $0) }.joined()
        } else {
            hash = "empty"
        }
        
        return try generateSigil(payloadHash: hash, status: status)
    }
    
    // MARK: - Cryptogram Generation 
    
    func generateCryptogram(nonce: Data) throws -> Data {
        guard licenseKey != nil else {
            throw AranError.notInitialized
        }
        
        // Build attestation payload
        let status = AranSecure.shared.getCurrentStatus()
        let attestation: [String: Any] = [
            "nonce": nonce.base64EncodedString(),
            "timestamp": Int(Date().timeIntervalSince1970),
            "deviceFingerprint": status.deviceFingerprint,
            "threatStatus": status.toDictionary()
        ]
        
        guard let attestationData = try? JSONSerialization.data(withJSONObject: attestation) else {
            throw AranError.sigilGenerationFailed
        }
        
        // Sign the attestation
        let signatureData: Data
        if let secureKey = secureEnclaveKey {
            let signature = try secureKey.signature(for: attestationData)
            signatureData = signature.rawRepresentation
        } else if let regKey = regularKey {
            let signature = try regKey.signature(for: attestationData)
            signatureData = signature.rawRepresentation
        } else {
            throw AranError.secureEnclaveUnavailable
        }
        
        // Combine attestation + signature
        let result: [String: Any] = [
            "attestation": attestationData.base64EncodedString(),
            "signature": signatureData.base64EncodedString()
        ]
        
        guard let resultData = try? JSONSerialization.data(withJSONObject: result) else {
            throw AranError.sigilGenerationFailed
        }
        
        return resultData
    }
    
    // MARK: - Signature Generation  getSignature)
    
    func generateSignature(uuid: String) throws -> String {
        guard licenseKey != nil else {
            throw AranError.notInitialized
        }
        
        let payload: [String: Any] = [
            "uuid": uuid,
            "timestamp": Int(Date().timeIntervalSince1970),
            "bundleId": Bundle.main.bundleIdentifier ?? "unknown"
        ]
        
        guard let payloadData = try? JSONSerialization.data(withJSONObject: payload) else {
            throw AranError.sigilGenerationFailed
        }
        
        let signatureData: Data
        if let secureKey = secureEnclaveKey {
            let signature = try secureKey.signature(for: payloadData)
            signatureData = signature.rawRepresentation
        } else if let regKey = regularKey {
            let signature = try regKey.signature(for: payloadData)
            signatureData = signature.rawRepresentation
        } else {
            throw AranError.secureEnclaveUnavailable
        }
        
        return signatureData.base64URLEncodedString()
    }
}

// MARK: - Base64 URL Encoding

extension Data {
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// MARK: - Aran Errors

enum AranError: Error, LocalizedError {
    case notInitialized
    case sigilGenerationFailed
    case secureEnclaveUnavailable
    case invalidArgument(String)
    case secretVaultError(String)
    
    var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "Aran SDK not initialized. Call AranSecure.start() first."
        case .sigilGenerationFailed:
            return "Failed to generate Sigil/JWT token."
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this device."
        case .invalidArgument(let msg):
            return "Invalid argument: \(msg)"
        case .secretVaultError(let msg):
            return "Secret vault error: \(msg)"
        }
    }
}
