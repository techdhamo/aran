// Copyright 2024-2026 Mazhai Technologies
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

internal class AranURLProtocol: URLProtocol {
    
    private static let handledKey = "AranURLProtocolHandled"
    
    // Hosts that must pass through C-level zero-knowledge pin validation
    private static let pinnedHosts: Set<String> = [
        "api.aran.mazhai.org",
        "aran.mazhai.org"
    ]
    
    private var session: URLSession?
    private var sessionTask: URLSessionDataTask?
    
    override class func canInit(with request: URLRequest) -> Bool {
        if URLProtocol.property(forKey: handledKey, in: request) != nil {
            return false
        }
        
        guard let scheme = request.url?.scheme?.lowercased() else {
            return false
        }
        
        return scheme == "http" || scheme == "https"
    }
    
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }
    
    override func startLoading() {
        // ── Scorched Earth Network Blackhole ──
        // If the device is compromised, IMMEDIATELY halt ALL network requests.
        // No data leaves the device. The app is deaf and mute on the wire.
        if g_aran_is_compromised {
            let blackholeError = NSError(
                domain: NSURLErrorDomain,
                code: NSURLErrorSecureConnectionFailed,
                userInfo: [NSLocalizedDescriptionKey: "Network access revoked by security policy"]
            )
            client?.urlProtocol(self, didFailWithError: blackholeError)
            return
        }

        guard let mutableRequest = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "AranURLProtocol", code: -1, userInfo: nil))
            return
        }
        
        URLProtocol.setProperty(true, forKey: AranURLProtocol.handledKey, in: mutableRequest)
        
        do {
            let status = AranSecure.shared.getCurrentStatus()
            let sigil = try AranSigilEngine.shared.generateSigilForRequest(
                requestBody: request.httpBody,
                status: status
            )
            
            mutableRequest.setValue(sigil, forHTTPHeaderField: "X-Aran-Sigil")
            
        } catch {
            #if DEBUG
            print("Aran: Failed to generate Sigil for request: \(error)")
            #endif
        }
        
        let configuration = URLSessionConfiguration.default
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        sessionTask = session?.dataTask(with: mutableRequest as URLRequest)
        sessionTask?.resume()
    }
    
    override func stopLoading() {
        sessionTask?.cancel()
        session?.invalidateAndCancel()
    }
}

extension AranURLProtocol: URLSessionDataDelegate {
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .allowed)
        completionHandler(.allow)
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        client?.urlProtocol(self, didLoad: data)
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error {
            client?.urlProtocol(self, didFailWithError: error)
        } else {
            client?.urlProtocolDidFinishLoading(self)
        }
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        client?.urlProtocol(self, wasRedirectedTo: request, redirectResponse: response)
        completionHandler(request)
    }
    
    // MARK: - Zero-Knowledge Certificate Pinning via C Core
    //
    // For pinned hosts (api.aran.mazhai.org):
    // 1. Extract leaf certificate     // 2. SHA-256 hash the DER-encoded certificate
    // 3. Pass hash to aran_verify_cert_blinded() in C core
    // 4. C core blinds the hash with salt, compares against stored blinded pins
    // 5. Expected pin NEVER exists in plaintext RAM
    // 6. If invalid → cancel connection immediately
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let host = challenge.protectionSpace.host
        
        // Non-pinned hosts: allow default TLS handling
        guard AranURLProtocol.pinnedHosts.contains(host) else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Extract leaf certificate         let leafCert: SecCertificate?
        if #available(iOS 15.0, *) {
            leafCert = (SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate])?.first
        } else {
            leafCert = SecTrustGetCertificateCount(serverTrust) > 0
                ? SecTrustGetCertificateAtIndex(serverTrust, 0)
                : nil
        }
        guard let cert = leafCert else {
            // No certificate in chain — MITM or misconfigured server
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // SHA-256 hash of the DER-encoded leaf certificate
        let certData = SecCertificateCopyData(cert) as Data
        let certHash = SHA256.hash(data: certData)
        let hashBytes = Array(certHash)
        
        // Route to C-level zero-knowledge blinded pin validator
        // aran_verify_cert_blinded() applies cryptographic salt and compares
        // against Genesis/Dynamic pins WITHOUT ever decrypting the pin into RAM
        let isValid = hashBytes.withUnsafeBufferPointer { ptr -> Bool in
            guard let baseAddress = ptr.baseAddress else { return false }
            return aran_verify_cert_blinded(baseAddress, UInt32(ptr.count)) == 1
        }
        
        if isValid {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // PIN MISMATCH — possible MITM attack. Kill the connection.
            #if DEBUG
            print("Aran/URLProtocol: Certificate pin FAILED for host: \(host)")
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
