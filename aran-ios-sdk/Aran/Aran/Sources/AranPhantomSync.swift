// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Phantom Channel — HTTP/3 QUIC over UDP Configuration Sync
//
// Architecture:
// 1. NWConnection with QUIC (NWParameters.quic) over UDP port 443
// 2. Bypasses standard HTTP proxy interception (no URLSession)
// 3. Fetches dynamic config -central, decrypts via Secure Enclave
// 4. Verifies backend HMAC signature on payload
// 5. Updates local hardware-sealed state (Keychain + Genesis dynamic pins)
// 6. On MITM detection → immediate KILL_APP via AranThreatListener
//
// The Phantom Channel runs as a background async task, completely invisible
// to any URLSession-based proxy or network interceptor.

import Foundation
import Network
import CryptoKit

@available(iOS 15.0, *)
internal final class AranPhantomSync {
    
    static let shared = AranPhantomSync()
    
    // MARK: - State
    
    private var connection: NWConnection?
    private var syncTimer: DispatchSourceTimer?
    private var isRunning = false
    private var lastSyncTimestamp: TimeInterval = 0
    private var syncIntervalSeconds: UInt32 = 60
    
    // Sealed genesis state (loaded once, updated by phantom sync)
    private var sealedAESKey: SymmetricKey?
    private var sealedHMACKey: SymmetricKey?
    private var sealedEndpoint: String = ""
    private var licenseKey: String = ""
    
    private let syncQueue = DispatchQueue(label: "org.mazhai.aran.phantom", qos: .utility)
    
    private init() {}
    
    // MARK: - Lifecycle
    
    func start(licenseKey: String, genesisState: UnsafeMutablePointer<AranGenesisState>) {
        guard !isRunning else { return }
        isRunning = true
        self.licenseKey = licenseKey
        
        // Seal genesis cryptographic material into Swift CryptoKit keys
        sealedAESKey = SymmetricKey(data: Data(bytes: &genesisState.pointee.aes_key,
                                               count: Int(ARAN_GENESIS_AES_KEY_LEN)))
        sealedHMACKey = SymmetricKey(data: Data(bytes: &genesisState.pointee.hmac_secret,
                                                count: Int(ARAN_GENESIS_HMAC_SECRET_LEN)))
        sealedEndpoint = String(cString: &genesisState.pointee.sync_endpoint.0)
        syncIntervalSeconds = genesisState.pointee.sync_interval_seconds
        
        // Store sealed keys in Keychain (hardware-backed on devices with Secure Enclave)
        sealToKeychain()
        
        // Start periodic sync
        startSyncTimer()
        
        // Trigger immediate first sync
        syncQueue.async { [weak self] in
            self?.performPhantomSync()
        }
    }
    
    func stop() {
        isRunning = false
        syncTimer?.cancel()
        syncTimer = nil
        connection?.cancel()
        connection = nil
    }
    
    // MARK: - QUIC Connection (Phantom Channel)
    
    private func performPhantomSync() {
        guard isRunning else { return }
        
        // Parse endpoint host /dynamic config
        guard let endpointHost = extractHost(from: sealedEndpoint) else {
            #if DEBUG
            print("Aran/Phantom: Invalid endpoint: \(sealedEndpoint)")
            #endif
            return
        }
        
        // Build QUIC parameters — UDP port 443, TLS 1.3 mandatory
        let quicParams = NWParameters.quic(alpn: ["h3"])
        
        // Enforce TLS 1.3 minimum
        if let tlsOptions = quicParams.defaultProtocolStack.applicationProtocols.first as? NWProtocolTLS.Options {
            sec_protocol_options_set_min_tls_protocol_version(
                tlsOptions.securityProtocolOptions,
                .TLSv13
            )
            
            // Install custom TLS verification that routes through C-level blinded pin validator
            sec_protocol_options_set_verify_block(
                tlsOptions.securityProtocolOptions,
                { [weak self] (metadata, trust, completion) in
                    self?.verifyServerCertificate(metadata: metadata, trust: trust, completion: completion)
                },
                syncQueue
            )
        }
        
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(endpointHost),
            port: NWEndpoint.Port(integerLiteral: 443)
        )
        
        connection = NWConnection(to: endpoint, using: quicParams)
        
        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.sendConfigRequest()
            case .failed(let error):
                #if DEBUG
                print("Aran/Phantom: Connection failed: \(error)")
                #endif
                self?.connection?.cancel()
                self?.connection = nil
            case .waiting(let error):
                #if DEBUG
                print("Aran/Phantom: Waiting: \(error)")
                #endif
            default:
                break
            }
        }
        
        connection?.start(queue: syncQueue)
    }
    
    // MARK: - TLS Verification (routes to C-level aran_verify_cert_blinded)
    
    private func verifyServerCertificate(
        metadata: sec_protocol_metadata_t,
        trust: sec_trust_t,
        completion: @escaping (Bool) -> Void
    ) {
        let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
        
        let leafCert: SecCertificate?
        if #available(iOS 15.0, *) {
            leafCert = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate])?.first
        } else {
            leafCert = SecTrustGetCertificateCount(secTrust) > 0
                ? SecTrustGetCertificateAtIndex(secTrust, 0)
                : nil
        }
        guard let cert = leafCert else {
            // No certificate — MITM detected
            triggerMITMKill(reason: "No server certificate in QUIC handshake")
            completion(false)
            return
        }
        
        // SHA-256 hash of DER-encoded leaf certificate
        let certData = SecCertificateCopyData(cert) as Data
        let certHash = SHA256.hash(data: certData)
        let hashBytes = Array(certHash)
        
        // Route to C-level zero-knowledge blinded pin validator
        let isValid = hashBytes.withUnsafeBufferPointer { ptr -> Bool in
            guard let baseAddress = ptr.baseAddress else { return false }
            return aran_verify_cert_blinded(baseAddress, UInt32(ptr.count)) == 1
        }
        
        if isValid {
            completion(true)
        } else {
            // MITM DETECTED on Phantom Channel — invoke KILL_APP immediately
            triggerMITMKill(reason: "Certificate pin mismatch on Phantom QUIC channel")
            completion(false)
        }
    }
    
    // MARK: - Request / Response
    
    private func sendConfigRequest() {
        guard let connection = connection else { return }
        
        let nonce = UUID().uuidString
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        
        // Build minimal HTTP/3-style request payload
        let requestPayload: [String: Any] = [
            "method": "GET",
            "path": "/api/v1/config/sync",
            "os": "ios",
            "rasp_version": AranSecure.sdkVersion,
            "license_key": licenseKey,
            "nonce": nonce,
            "timestamp": timestamp
        ]
        
        guard let requestData = try? JSONSerialization.data(withJSONObject: requestPayload) else { return }
        
        // Sign the request with HMAC
        if let hmacKey = sealedHMACKey {
            let signature = HMAC<SHA256>.authenticationCode(for: requestData, using: hmacKey)
            
            // Prepend 32-byte HMAC signature to request data
            var signedPayload = Data(signature)
            signedPayload.append(requestData)
            
            connection.send(content: signedPayload, completion: .contentProcessed { [weak self] error in
                if let error = error {
                    #if DEBUG
                    print("Aran/Phantom: Send failed: \(error)")
                    #endif
                    return
                }
                self?.receiveConfigResponse(nonce: nonce, timestamp: timestamp)
            })
        }
    }
    
    private func receiveConfigResponse(nonce: String, timestamp: Int64) {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self = self, let data = data, data.count > 32 else {
                #if DEBUG
                if let error = error {
                    print("Aran/Phantom: Receive failed: \(error)")
                }
                #endif
                self?.connection?.cancel()
                self?.connection = nil
                return
            }
            
            // First 32 bytes = backend HMAC signature, rest = encrypted payload
            let backendSignature = data.prefix(32)
            let encryptedPayload = data.dropFirst(32)
            
            // Verify backend HMAC signature
            guard let hmacKey = self.sealedHMACKey else { return }
            let computedSignature = HMAC<SHA256>.authenticationCode(for: encryptedPayload, using: hmacKey)
            
            guard Data(computedSignature) == backendSignature else {
                self.triggerMITMKill(reason: "HMAC signature mismatch on Phantom Channel response")
                return
            }
            
            // Decrypt with AES-256-GCM
            guard let aesKey = self.sealedAESKey else { return }
            let aad = "\(nonce):\(timestamp)"
            
            do {
                guard encryptedPayload.count > 28 else { return } // 12 IV + 16 tag minimum
                let iv = encryptedPayload.prefix(12)
                let ciphertextAndTag = encryptedPayload.dropFirst(12)
                
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: iv),
                    ciphertext: ciphertextAndTag.dropLast(16),
                    tag: ciphertextAndTag.suffix(16)
                )
                
                let decrypted = try AES.GCM.open(
                    sealedBox,
                    using: aesKey,
                    authenticating: Data(aad.utf8)
                )
                
                self.processDecryptedConfig(decrypted)
                self.lastSyncTimestamp = Date().timeIntervalSince1970
                
            } catch {
                #if DEBUG
                print("Aran/Phantom: Decryption failed: \(error)")
                #endif
            }
            
            self.connection?.cancel()
            self.connection = nil
        }
    }
    
    // MARK: - Config Processing
    
    private func processDecryptedConfig(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            #if DEBUG
            print("Aran/Phantom: Invalid JSON in decrypted config")
            #endif
            return
        }
        
        // Update dynamic TLS pins if present (blinded form )
        if let pins = json["tls_pins_blinded"] as? [[String: Any]] {
            updateDynamicPins(from: pins)
        }
        
        // Update sync interval if present
        if let interval = json["sync_interval_seconds"] as? UInt32 {
            syncIntervalSeconds = interval
        }
        
        // Update sealed AES/HMAC keys if backend rotated them
        if let newAesKeyB64 = json["rotated_aes_key"] as? String,
           let aesData = Data(base64Encoded: newAesKeyB64), aesData.count == 32 {
            sealedAESKey = SymmetricKey(data: aesData)
            sealToKeychain()
        }
        
        if let newHmacB64 = json["rotated_hmac_secret"] as? String,
           let hmacData = Data(base64Encoded: newHmacB64), hmacData.count == 32 {
            sealedHMACKey = SymmetricKey(data: hmacData)
            sealToKeychain()
        }
        
        // Update reaction policy if present
        if let policyRaw = json["default_reaction_policy"] as? Int,
           let policy = ReactionPolicy(rawValue: policyRaw) {
            AranSecure.shared.updateReactionPolicyFromPhantom(policy)
        }
        
        #if DEBUG
        print("Aran/Phantom: Config synced successfully at \(Date())")
        #endif
    }
    
    private func updateDynamicPins(: [[String: Any]]) {
        guard pins.count >= 2 else { return }
        
        guard let pin0B64 = pins[0]["blinded"] as? String,
              let pin1B64 = pins[1]["blinded"] as? String,
              let pin0Data = Data(base64Encoded: pin0B64),
              let pin1Data = Data(base64Encoded: pin1B64) else { return }
        
        // Update C-level dynamic pin storage
        pin0Data.withUnsafeBytes { p0 in
            pin1Data.withUnsafeBytes { p1 in
                guard let p0Base = p0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let p1Base = p1.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                aran_genesis_update_dynamic_pins(
                    p0Base, UInt32(pin0Data.count),
                    p1Base, UInt32(pin1Data.count)
                )
            }
        }
    }
    
    // MARK: - MITM Kill
    
    private func triggerMITMKill(reason: String) {
        #if DEBUG
        print("Aran/Phantom: SECURITY ALERT — \(reason)")
        #endif
        
        // Immediately invoke the threat listener with KILL_APP policy
        DispatchQueue.main.async {
            let status = AranSecure.shared.getCurrentStatus()
            AranSecure.shared.invokeThreatListener(status: status, overridePolicy: .killApp)
        }
        
        // Cancel all connections
        connection?.cancel()
        connection = nil
    }
    
    // MARK: - Sync Timer
    
    private func startSyncTimer() {
        syncTimer?.cancel()
        
        let timer = DispatchSource.makeTimerSource(queue: syncQueue)
        timer.schedule(
            deadline: .now() + .seconds(Int(syncIntervalSeconds)),
            repeating: .seconds(Int(syncIntervalSeconds)),
            leeway: .seconds(5)
        )
        timer.setEventHandler { [weak self] in
            self?.performPhantomSync()
        }
        timer.resume()
        syncTimer = timer
    }
    
    // MARK: - Keychain Seal
    
    private func sealToKeychain() {
        guard let aesKey = sealedAESKey, let hmacKey = sealedHMACKey else { return }
        
        let aesData = aesKey.withUnsafeBytes { Data($0) }
        let hmacData = hmacKey.withUnsafeBytes { Data($0) }
        
        storeInKeychain(data: aesData, account: "org.mazhai.aran.phantom.aes")
        storeInKeychain(data: hmacData, account: "org.mazhai.aran.phantom.hmac")
        storeInKeychain(data: Data(sealedEndpoint.utf8), account: "org.mazhai.aran.phantom.endpoint")
    }
    
    func restoreFromKeychain() -> Bool {
        guard let aesData = loadFromKeychain(account: "org.mazhai.aran.phantom.aes"),
              let hmacData = loadFromKeychain(account: "org.mazhai.aran.phantom.hmac"),
              let endpointData = loadFromKeychain(account: "org.mazhai.aran.phantom.endpoint") else {
            return false
        }
        
        sealedAESKey = SymmetricKey(data: aesData)
        sealedHMACKey = SymmetricKey(data: hmacData)
        sealedEndpoint = String(data: endpointData, encoding: .utf8) ?? ""
        return !sealedEndpoint.isEmpty
    }
    
    private func storeInKeychain(data: Data, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "org.mazhai.aran.phantom",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data
        ]
        
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    private func loadFromKeychain(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "org.mazhai.aran.phantom",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess ? result as? Data : nil
    }
    
    // MARK: - Helpers
    
    private func extractHost(: String) -> String? {
        guard let url = URL(string: urlString) else { return nil }
        return url.host
    }
    
    func getLastSyncTimestamp() -> TimeInterval {
        return lastSyncTimestamp
    }
}
