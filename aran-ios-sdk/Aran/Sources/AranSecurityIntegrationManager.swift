import Foundation
import Security
import Network

/**
 * Central security integration manager that coordinates all security components
 * Provides unified interface for anti-Frida, certificate pinning, and device fingerprinting
 */
public class AranSecurityIntegrationManager {
    
    public static let shared = AranSecurityIntegrationManager()
    
    private var initialized = false
    private let antiFrida = AranAntiFrida.shared
    private let certificatePinning = AranEnhancedCertificatePinning.shared
    private let securityHardening = AranSecurityHardening.shared
    private let advancedAntiFrida = AranAdvancedAntiFrida.shared
    private let raspDefense = AranRASPDefense.shared
    private let advancedRASPDefense = AranAdvancedRASPDefense.shared
    private let fintechSecurity = AranFintechSecurity.shared
    private let raspCoreEngine = AranRaspCoreEngine.shared
    
    public interface SecurityInitializationCallback {
        func onSecurityInitialized()
        func onSecurityInitializationFailed(reason: String)
        func onSecurityBreach(reason: String)
    }
    
    private init() {}
    
    // MARK: - Public Interface
    
    /**
     * Initialize all security components
     */
    public func initializeSecurity(callback: SecurityInitializationCallback? = nil) {
        guard !initialized else {
            aran_log("Security already initialized")
            callback?.onSecurityInitialized()
            return
        }
        
        DispatchQueue.global(qos: .userInitiated).async {
            aran_log("========================================")
            aran_log("Initializing Enhanced Security Framework with Hardening")
            aran_log("========================================")
            
            // Step 1: Initialize Native Core Engine (90% of logic in Swift/C)
            aran_log("Step 1: Initializing Native Core Engine...")
            self.raspCoreEngine.initialize()
            
            // Step 2: Initialize fintech security
            aran_log("Step 2: Initializing fintech security...")
            self.fintechSecurity.initialize()
            
            // Step 3: Initialize advanced RASP defense
            aran_log("Step 3: Initializing advanced RASP defense...")
            self.advancedRASPDefense.initialize()
            
            // Step 4: Initialize RASP defense layers
            aran_log("Step 4: Initializing RASP defense layers...")
            self.raspDefense.initialize()
            
            // Step 5: Initialize advanced anti-Frida detection
            aran_log("Step 5: Initializing advanced anti-Frida detection...")
            self.advancedAntiFrida.initialize()
            
            // Step 6: Perform advanced anti-Frida check
            aran_log("Step 6: Performing advanced anti-Frida check...")
            let advancedResult = self.advancedAntiFrida.performComprehensiveAdvancedCheck()
            
            if advancedResult.securityBreach {
                aran_log("Advanced anti-Frida threat detected: \(advancedResult.threatsDetected) threats")
                callback?.onSecurityBreach("Advanced Frida bypass detected: \(advancedResult.threatsDetected) threats")
                self.triggerEmergencyShutdown("Advanced Frida bypass detected")
                return
            }
            
            aran_log("Advanced anti-Frida check PASSED")
            
            // Step 7: Perform Native Core Engine check (90% of logic in Swift/C)
            aran_log("Step 7: Performing Native Core Engine check...")
            self.raspCoreEngine.validateEnvironment(riskContext: AranFintechSecurity.FINANCE_SENSITIVE_CONTEXT)
            
            if self.raspCoreEngine.getCurrentState() == AranRaspCoreEngine.CONFIRMED_TAMPER {
                aran_log("Native Core Engine detected CONFIRMED_TAMPER")
                callback?.onSecurityBreach("Native Core Engine: Confirmed tamper detected")
                self.triggerEmergencyShutdown("Native Core Engine: Confirmed tamper detected")
                return
            }
            
            aran_log("Native Core Engine check PASSED (state: \(self.raspCoreEngine.getCurrentState()))")
            
            // Step 8: Perform advanced RASP check
            aran_log("Step 8: Performing advanced RASP check...")
            let advancedRASPResult = self.advancedRASPDefense.performComprehensiveAdvancedRASPCheck()
            
            if advancedRASPResult.securityBreach {
                aran_log("Advanced RASP threat detected: \(advancedRASPResult.threatsDetected) threats")
                callback?.onSecurityBreach("Advanced RASP bypass detected: \(advancedRASPResult.threatsDetected) threats")
                self.triggerEmergencyShutdown("Advanced RASP bypass detected")
                return
            }
            
            aran_log("Advanced RASP check PASSED")
            
            // Step 9: Perform fintech security check
            aran_log("Step 9: Performing fintech security check...")
            let fintechResult = self.fintechSecurity.performComprehensiveFintechCheck()
            
            if fintechResult.riskLevel == .critical {
                aran_log("CRITICAL fintech risk detected")
                callback?.onSecurityBreach("Critical fintech security risk")
                self.triggerEmergencyShutdown("Critical fintech security risk")
                return
            }
            
            aran_log("Fintech security check PASSED (risk: \(fintechResult.riskLevel))")
            
            // Step 10: Perform RASP defense check
            aran_log("Step 10: Performing RASP defense check...")
            let raspStatus = self.raspDefense.getRASPStatus()
            
            if !raspStatus.stringEncryptionWorking || !raspStatus.cyclicChecksActive {
                aran_log("RASP defense compromised: encryption=\(raspStatus.stringEncryptionWorking), cyclic=\(raspStatus.cyclicChecksActive)")
                callback?.onSecurityBreach("RASP defense compromised")
                self.triggerEmergencyShutdown("RASP defense compromised")
                return
            }
            
            aran_log("RASP defense check PASSED")
            
            // Step 11: Perform comprehensive security hardening check
            aran_log("Step 11: Performing comprehensive security hardening check...")
            let hardeningResult = self.securityHardening.performComprehensiveSecurityCheck()
            
            if hardeningResult.securityBreach {
                aran_log("Security breach detected during hardening: \(hardeningResult.breachReason)")
                callback?.onSecurityBreach(hardeningResult.breachReason)
                self.triggerEmergencyShutdown(hardeningResult.breachReason)
                return
            }
            
            aran_log("Security hardening check PASSED")
            
            // Step 12: Initialize Anti-Frida detection
            aran_log("Step 12: Initializing Anti-Frida detection...")
            self.performAntiFridaCheck { success in
                if success {
                    aran_log("Anti-Frida integrity verified")
                    self.continueInitialization(callback: callback)
                } else {
                    aran_log("Anti-Frida check failed")
                    callback?.onSecurityBreach("Anti-Frida detection failed")
                    self.triggerEmergencyShutdown("Anti-Frida detection failed")
                }
            }
        }
    }
    
    /**
     * Perform comprehensive security verification
     */
    public func performComprehensiveVerification(callback: SecurityInitializationCallback? = nil) {
        guard initialized else {
            aran_log("Security not initialized, performing initialization first")
            initializeSecurity(callback: callback)
            return
        }
        
        DispatchQueue.global(qos: .userInitiated).async {
            aran_log("Starting comprehensive security verification...")
            
            self.performAntiFridaCheck { success in
                if success {
                    aran_log("Comprehensive security verification PASSED")
                    callback?.onSecurityInitialized()
                } else {
                    aran_log("Comprehensive security verification FAILED")
                    callback?.onSecurityBreach("Security verification failed")
                    self.triggerEmergencyShutdown("Security verification failed")
                }
            }
        }
    }
    
    /**
     * Get device fingerprint for server communication
     */
    public func getDeviceFingerprint() -> String {
        guard initialized else {
            aran_log("Security not initialized, returning fallback fingerprint")
            return "fallback_\(Date().timeIntervalSince1970)"
        }
        
        return antiFrida.getDeviceFingerprint()
    }
    
    /**
     * Apply enhanced certificate pinning to URLSession
     */
    public func applyCertificatePinning(to session: URLSession, hostname: String) {
        guard initialized else {
            aran_log("Security not initialized, skipping certificate pinning")
            return
        }
        
        certificatePinning.applyToURLSession(session, hostname: hostname)
    }
    
    /**
     * Generate secure nonce for API requests
     */
    public func generateSecureNonce() -> String {
        let data = Data(count: 32)
        _ = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, 32, bytes.baseAddress!)
        }
        return data.base64EncodedString()
    }
    
    /**
     * Validate response timing to detect MITM
     */
    public func validateResponseTiming(startTime: CFTimeInterval, endTime: CFTimeInterval) -> Bool {
        let duration = endTime - startTime
        
        // If response is too fast (< 50ms) or too slow (> 10 seconds), suspicious
        if duration < 0.05 || duration > 10.0 {
            aran_log("Suspicious response timing: \(duration * 1000)ms")
            return false
        }
        
        return true
    }
    
    /**
     * Get security statistics
     */
    public func getSecurityStatistics() -> SecurityStatistics {
        return SecurityStatistics(
            initialized: initialized,
            fridaDetected: antiFrida.detectFrida(),
            sslTamperingDetected: certificatePinning.detectSSLTampering(),
            hardeningResult: securityHardening.performComprehensiveSecurityCheck(),
            advancedResult: advancedAntiFrida.performComprehensiveAdvancedCheck(),
            raspStatus = raspDefense.getRASPStatus(),
            advancedRASPResult = advancedRASPDefense.performComprehensiveAdvancedRASPCheck(),
            fintechResult = fintechSecurity.performComprehensiveFintechCheck(),
            raspCoreStatus = raspCoreEngine.getSecurityStatus()
        )
    }
    
    /**
     * Check if security is initialized
     */
    public func isInitialized() -> Bool {
        return initialized
    }
    
    /**
     * Reset security (for testing purposes only)
     */
    public func resetForTesting() {
        initialized = false
    }
    
    /**
     * Get individual security components (for advanced usage)
     */
    public func getAntiFrida() -> AranAntiFrida {
        return antiFrida
    }
    
    public func getCertificatePinning() -> AranEnhancedCertificatePinning {
        return certificatePinning
    }
    
    /**
     * Shutdown all security components
     */
    public func shutdown() {
        aran_log("Shutting down security framework...")
        
        antiFrida.stopMonitoring()
        initialized = false
        
        aran_log("Security framework shutdown complete")
    }
    
    // MARK: - Private Methods
    
    /**
     * Continue initialization after Anti-Frida check
     */
    private func continueInitialization(callback: SecurityInitializationCallback? = nil) {
        DispatchQueue.global(qos: .userInitiated).async {
            // Step 2: Validate certificate pinning
            aran_log("Step 2: Validating enhanced certificate pinning...")
            let certValidation = self.certificatePinning.validateConnectionSecurity(hostname: "api.dhamo.in", port: 443)
            
            if !certValidation {
                aran_log("Certificate pinning validation failed")
                callback?.onSecurityInitializationFailed("Certificate pinning validation failed")
                return
            }
            
            // Step 3: Generate device fingerprint
            aran_log("Step 3: Generating device fingerprint...")
            let fingerprint = self.antiFrida.getDeviceFingerprint()
            aran_log("Device fingerprint generated: \(String(fingerprint.prefix(16)))...")
            
            // Step 4: Start continuous monitoring
            aran_log("Step 4: Starting continuous monitoring...")
            self.antiFrida.startMonitoring()
            
            self.initialized = true
            aran_log("Enhanced Security Framework initialized successfully")
            aran_log("========================================")
            
            DispatchQueue.main.async {
                callback?.onSecurityInitialized()
            }
        }
    }
    
    /**
     * Perform Anti-Frida check
     */
    private func performAntiFridaCheck(completion: @escaping (Bool) -> Void) {
        // Check for SSL tampering first
        if certificatePinning.detectSSLTampering() {
            aran_log("SSL tampering detected during Anti-Frida check")
            completion(false)
            return
        }
        
        // Perform Anti-Frida detection
        let fridaDetected = antiFrida.detectFrida()
        
        if fridaDetected {
            aran_log("Frida detected during security check")
            completion(false)
        } else {
            // Verify app integrity
            let integrityValid = antiFrida.verifyAppIntegrity()
            completion(integrityValid)
        }
    }
    
    /**
     * Emergency shutdown in case of security breach
     */
    private func triggerEmergencyShutdown(_ reason: String) {
        aran_log("EMERGENCY SHUTDOWN TRIGGERED: \(reason)")
        
        // Kill app immediately
        exit(1)
    }
    
    /**
     * Get SecurityHardening component
     */
    public func getSecurityHardening() -> AranSecurityHardening {
        return securityHardening
    }
    
    /**
     * Get AdvancedAntiFrida component
     */
    public func getAdvancedAntiFrida() -> AranAdvancedAntiFrida {
        return advancedAntiFrida
    }
    
    /**
     * Get AranRASPDefense component
     */
    public func getRASPDefense() -> AranRASPDefense {
        return raspDefense
    }
    
    /**
     * Get AranAdvancedRASPDefense component
     */
    public func getAdvancedRASPDefense() -> AranAdvancedRASPDefense {
        return advancedRASPDefense
    }
    
    /**
     * Get AranFintechSecurity component
     */
    public func getFintechSecurity() -> AranFintechSecurity {
        return fintechSecurity
    }
    
    /**
     * Get AranRaspCoreEngine component
     */
    public func getRaspCoreEngine() -> AranRaspCoreEngine {
        return raspCoreEngine
    }
}

// MARK: - Security Statistics

/**
 * Security statistics class
 */
public struct SecurityStatistics {
    public let initialized: Bool
    public let fridaDetected: Bool
    public let sslTamperingDetected: Bool
    public let hardeningResult: AranSecurityHardening.SecurityCheckResult
    public let advancedResult: AranAdvancedAntiFrida.AdvancedCheckResult
    public let raspStatus: AranRASPDefense.RASPStatus
    public let advancedRASPResult: AranAdvancedRASPDefense.AdvancedRASPResult
    public let fintechResult: AranFintechSecurity.FintechSecurityResult
    public let raspCoreStatus: AranRaspCoreEngine.SecurityStatus
    
    public var description: String {
        return "Security Stats{initialized=\(initialized), frida=\(fridaDetected), sslTampering=\(sslTamperingDetected), breach=\(hardeningResult.securityBreach), advancedBreach=\(advancedResult.securityBreach), raspCompromised=\(!raspStatus.stringEncryptionWorking || !raspStatus.cyclicChecksActive), advancedRASPBreach=\(advancedRASPResult.securityBreach), fintechRisk=\(fintechResult.riskLevel), coreState=\(raspCoreStatus.currentState)}"
    }
}
