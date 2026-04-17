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

internal class AranURLProtocol: URLProtocol {
    
    private static let handledKey = "AranURLProtocolHandled"
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
            print("Aran: Failed to generate Sigil for request: \(error)")
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
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let host = challenge.protectionSpace.host
        let pinnedHosts: [String: Set<String>] = [
            "api.aran.mazhai.org": [
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
            ]
        ]
        
        // If not a pinned host, allow default handling
        guard let expectedPins = pinnedHosts[host] else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Extract server certificate's SPKI SHA-256 and compare against pins
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        var pinMatched = false
        
        for i in 0..<certificateCount {
            guard let certificate = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
                  i < certificate.count else { continue }
            let certData = SecCertificateCopyData(certificate[i]) as Data
            var sha256 = Data(count: 32)
            sha256.withUnsafeMutableBytes { sha256Ptr in
                certData.withUnsafeBytes { certPtr in
                    _ = CC_SHA256(certPtr.baseAddress, CC_LONG(certData.count), sha256Ptr.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            let certPin = sha256.base64EncodedString()
            if expectedPins.contains(certPin) {
                pinMatched = true
                break
            }
        }
        
        if pinMatched {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
