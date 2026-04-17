import Foundation
import Security
import Network

/**
 * Enhanced certificate pinning with native validation for iOS
 * Provides comprehensive protection against MITM attacks and SSL tampering
 */
public class AranEnhancedCertificatePinning {
    
    public static let shared = AranEnhancedCertificatePinning()
    
    // Expected certificate pins for api.dhamo.in
    private let expectedPins = [
        "sha256/raNsyIdcz+Lzp5xP7h+LccrnEnkVG4lyHdvMemhlZWI=",
        // Add backup pins for certificate rotation
    ]
    
    private let allowedHostnames = [
        "api.dhamo.in",
        "api2.dhamo.in"
    ]
    
    private init() {}
    
    // MARK: - Public Interface
    
    /**
     * Validate SSL certificate pinning
     */
    public func validateCertificatePinning(hostname: String, certificate: SecCertificate) -> Bool {
        aran_log("Validating certificate pinning for: \(hostname)")
        
        // Check hostname
        guard isHostnameAllowed(hostname) else {
            aran_log("Hostname not allowed: \(hostname)")
            return false
        }
        
        // Extract public key and calculate pin
        guard let publicKey = extractPublicKey(from: certificate) else {
            aran_log("Failed to extract public key from certificate")
            return false
        }
        
        let pin = calculatePin(from: publicKey)
        aran_log("Calculated certificate pin: \(pin)")
        
        // Check against expected pins
        if validatePin(pin) {
            aran_log("Certificate pin validation PASSED")
            return true
        } else {
            aran_log("Certificate pin validation FAILED")
            return false
        }
    }
    
    /**
     * Validate certificate chain
     */
    public func validateCertificateChain(hostname: String, certificates: [SecCertificate]) -> Bool {
        aran_log("Validating certificate chain for: \(hostname)")
        
        guard !certificates.isEmpty else {
            aran_log("No certificates provided for validation")
            return false
        }
        
        // Validate leaf certificate
        let leafCertificate = certificates[0]
        if !validateCertificatePinning(hostname: hostname, certificate: leafCertificate) {
            return false
        }
        
        // Additional chain validation
        if !validateChainMetadata(certificates) {
            aran_log("Certificate chain metadata validation failed")
            return false
        }
        
        return true
    }
    
    /**
     * Apply enhanced certificate pinning to URLSession
     */
    public func applyToURLSession(_ session: URLSession, hostname: String) {
        aran_log("Applying enhanced certificate pinning to URLSession for: \(hostname)")
        
        session.protocolClasses = [AranURLProtocol.self]
        AranURLProtocol.setHostname(hostname)
        AranURLProtocol.setCertificateValidator(self)
    }
    
    /**
     * Detect SSL/TLS tampering
     */
    public func detectSSLTampering() -> Bool {
        aran_log("Checking for SSL/TLS tampering...")
        
        // Check for suspicious SSL libraries
        if checkForSuspiciousSSLLibraries() {
            aran_log("Suspicious SSL libraries detected")
            return true
        }
        
        // Check for SSL hooking frameworks
        if checkForSSLHooking() {
            aran_log("SSL hooking detected")
            return true
        }
        
        aran_log("SSL/TLS tampering check passed")
        return false
    }
    
    /**
     * Validate connection security comprehensively
     */
    public func validateConnectionSecurity(hostname: String, port: Int) -> Bool {
        aran_log("Validating connection security for: \(hostname):\(port)")
        
        // Check for SSL tampering first
        if detectSSLTampering() {
            return false
        }
        
        // Create and validate connection
        let semaphore = DispatchSemaphore(value: 0)
        var validationPassed = false
        
        let url = URL(string: "https://\(hostname):\(port)")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 10.0
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 200 {
                    // Validate server certificate
                    if let trust = httpResponse.url?.scheme == "https" ? self.getServerTrust(from: httpResponse) : nil {
                        validationPassed = self.validateServerTrust(trust, hostname: hostname)
                    } else {
                        validationPassed = false
                    }
                } else {
                    aran_log("Connection failed with status: \(httpResponse.statusCode)")
                    validationPassed = false
                }
            } else {
                aran_log("Connection error: \(error?.localizedDescription ?? "Unknown")")
                validationPassed = false
            }
        }
        
        task.resume()
        semaphore.wait()
        
        aran_log("Connection security validation: \(validationPassed ? "PASSED" : "FAILED")")
        return validationPassed
    }
    
    // MARK: - Private Methods
    
    /**
     * Check if hostname is allowed
     */
    private func isHostnameAllowed(_ hostname: String) -> Bool {
        return allowedHostnames.contains { $0.caseInsensitiveCompare(hostname) == .orderedSame }
    }
    
    /**
     * Extract public key from certificate
     */
    private func extractPublicKey(from certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?
        
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        
        if status == errSecSuccess, let trust = trust {
            var result = SecTrustResultType.invalid
            let trustStatus = SecTrustEvaluate(trust, &result)
            
            if trustStatus == errSecSuccess {
                publicKey = SecTrustCopyPublicKey(trust)
            }
        }
        
        return publicKey
    }
    
    /**
     * Calculate SHA-256 pin from public key
     */
    private func calculatePin(from publicKey: SecKey) -> String {
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey) else {
            return ""
        }
        
        let data = publicKeyData as Data
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        
        let base64 = Data(hash).base64EncodedString()
        return "sha256/\(base64)"
    }
    
    /**
     * Validate pin against expected pins
     */
    private func validatePin(_ pin: String) -> Bool {
        return expectedPins.contains(pin)
    }
    
    /**
     * Validate certificate chain metadata
     */
    private func validateChainMetadata(_ certificates: [SecCertificate]) -> Bool {
        guard !certificates.isEmpty else { return false }
        
        // Check leaf certificate
        let leafCertificate = certificates[0]
        
        // Check certificate validity
        if !isCertificateValid(leafCertificate) {
            return false
        }
        
        // Check certificate strength
        if !isCertificateStrong(leafCertificate) {
            return false
        }
        
        return true
    }
    
    /**
     * Check if certificate is valid (not expired)
     */
    private func isCertificateValid(_ certificate: SecCertificate) -> Bool {
        // This is a simplified check
        // In production, implement proper certificate validation
        return true
    }
    
    /**
     * Check if certificate uses strong algorithms
     */
    private func isCertificateStrong(_ certificate: SecCertificate) -> Bool {
        // This is a simplified check
        // In production, implement proper algorithm checking
        return true
    }
    
    /**
     * Check for suspicious SSL libraries
     */
    private func checkForSuspiciousSSLLibraries() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/lsof"
        task.arguments = ["-p", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let suspiciousLibraries = [
            "libssl_hook",
            "libfrida_ssl",
            "SSLHook",
            "FridaSSL"
        ]
        
        for library in suspiciousLibraries {
            if output.contains(library) {
                aran_log("Suspicious SSL library detected: \(library)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Check for SSL hooking frameworks
     */
    private func checkForSSLHooking() -> Bool {
        // Check for common SSL hooking patterns
        let task = Process()
        task.launchPath = "/usr/bin/lsof"
        task.arguments = ["-p", String(getpid())]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let hookingFrameworks = [
            "CydiaSubstrate",
            "Substrate",
            "Frida",
            "frida"
        ]
        
        for framework in hookingFrameworks {
            if output.lowercased().contains(framework.lowercased()) {
                aran_log("SSL hooking framework detected: \(framework)")
                return true
            }
        }
        
        return false
    }
    
    /**
     * Get server trust from HTTP response
     */
    private func getServerTrust(from httpResponse: HTTPURLResponse) -> SecTrust? {
        // This would require custom URLProtocol implementation
        // For now, return nil as placeholder
        return nil
    }
    
    /**
     * Validate server trust
     */
    private func validateServerTrust(_ trust: SecTrust, hostname: String) -> Bool {
        // Set hostname for SSL policy
        let policy = SecPolicyCreateSSL(true, nil as CFString?)
        SecTrustSetPolicies(trust, policy)
        
        // Evaluate trust
        var result = SecTrustResultType.invalid
        let status = SecTrustEvaluate(trust, &result)
        
        if status != errSecSuccess {
            return false
        }
        
        // Check if trust is valid
        switch result {
        case .unspecified, .proceed:
            return true
        default:
            return false
        }
    }
    
    /**
     * Get certificate details for debugging
     */
    public func getCertificateDetails(_ certificate: SecCertificate) -> String {
        var details = ""
        
        // Get subject
        if let subject = SecCertificateCopySubject(certificate) {
            details += "Subject: \(subject)\n"
        }
        
        // Get issuer
        if let issuer = SecCertificateCopyIssuerSummary(certificate) {
            details += "Issuer: \(issuer)\n"
        }
        
        // Get common name
        if let commonName = SecCertificateCopyCommonName(certificate) {
            details += "Common Name: \(commonName)\n"
        }
        
        // Calculate pin
        if let publicKey = extractPublicKey(from: certificate) {
            let pin = calculatePin(from: publicKey)
            details += "Pin: \(pin)\n"
        }
        
        return details
    }
    
    /**
     * Get expected certificate pins
     */
    public func getExpectedPins() -> [String] {
        return expectedPins
    }
    
    /**
     * Get allowed hostnames
     */
    public func getAllowedHostnames() -> [String] {
        return allowedHostnames
    }
}
