// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

import Foundation
import CryptoKit
import DeviceCheck

/// Phase 4: Hardware Attestation Engine
/// Uses DCAppAttestService for hardware-bound device integrity attestation.
@available(iOS 14.0, *)
internal class AranAppAttest {
    
    static let shared = AranAppAttest()
    
    private var keyId: String?
    private let keyIdStorageKey = "aran.appattest.keyid"
    
    private init() {
        keyId = UserDefaults.standard.string(forKey: keyIdStorageKey)
    }
    
    // MARK: - Key Generation
    
    /// Generate a new App Attest key and store its ID.
    func generateKey(completion: @escaping (Result<String, Error>) -> Void) {
        let service = DCAppAttestService.shared
        
        guard service.isSupported else {
            completion(.failure(AranAttestError.notSupported))
            return
        }
        
        service.generateKey { [weak self] keyId, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let keyId = keyId else {
                completion(.failure(AranAttestError.keyGenerationFailed))
                return
            }
            
            self?.keyId = keyId
            UserDefaults.standard.set(keyId, forKey: self?.keyIdStorageKey ?? "")
            completion(.success(keyId))
        }
    }
    
    // MARK: - Attestation
    
    /// Attest the key with Apple's servers, producing a hardware-bound attestation object.
    /// The clientDataHash should be a SHA256 hash of a server-provided challenge.
    func attestKey(clientDataHash: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let keyId = keyId else {
            // Auto-generate key first
            generateKey { [weak self] result in
                switch result {
                case .success:
                    self?.attestKey(clientDataHash: clientDataHash, completion: completion)
                case .failure(let error):
                    completion(.failure(error))
                }
            }
            return
        }
        
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            completion(.failure(AranAttestError.notSupported))
            return
        }
        
        service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let attestation = attestation else {
                completion(.failure(AranAttestError.attestationFailed))
                return
            }
            
            completion(.success(attestation))
        }
    }
    
    // MARK: - Assertion
    
    /// Generate an assertion for ongoing requests after initial attestation.
    /// This proves the request originates     func generateAssertion(clientDataHash: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let keyId = keyId else {
            completion(.failure(AranAttestError.keyNotGenerated))
            return
        }
        
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            completion(.failure(AranAttestError.notSupported))
            return
        }
        
        service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let assertion = assertion else {
                completion(.failure(AranAttestError.assertionFailed))
                return
            }
            
            completion(.success(assertion))
        }
    }
    
    // MARK: - Convenience: Attest with Challenge String
    
    /// Attest using a server-provided challenge string (hashed to SHA256 internally).
    func attest(challenge: String, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let challengeData = challenge.data(using: .utf8) else {
            completion(.failure(AranAttestError.invalidChallenge))
            return
        }
        
        let hash = Data(SHA256.hash(data: challengeData))
        attestKey(clientDataHash: hash, completion: completion)
    }
    
    /// Assert using a request payload (hashed to SHA256 internally).
    func assert(payload: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        let hash = Data(SHA256.hash(data: payload))
        generateAssertion(clientDataHash: hash, completion: completion)
    }
    
    // MARK: - Status
    
    var isSupported: Bool {
        return DCAppAttestService.shared.isSupported
    }
    
    var hasKey: Bool {
        return keyId != nil
    }
}

// MARK: - Errors

enum AranAttestError: Error, LocalizedError {
    case notSupported
    case keyGenerationFailed
    case keyNotGenerated
    case attestationFailed
    case assertionFailed
    case invalidChallenge
    
    var errorDescription: String? {
        switch self {
        case .notSupported: return "App Attest is not supported on this device."
        case .keyGenerationFailed: return "Failed to generate App Attest key."
        case .keyNotGenerated: return "No App Attest key. Call generateKey() first."
        case .attestationFailed: return "Key attestation failed."
        case .assertionFailed: return "Assertion generation failed."
        case .invalidChallenge: return "Invalid challenge data."
        }
    }
}
