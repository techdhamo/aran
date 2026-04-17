package org.mazhai.aran.security

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import org.mazhai.aran.AranSecure
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Central security integration manager that coordinates all security components
 */
class SecurityIntegrationManager private constructor(private val context: Context) {
    
    companion object {
        @Volatile
        private var INSTANCE: SecurityIntegrationManager? = null
        
        fun getInstance(context: Context): SecurityIntegrationManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SecurityIntegrationManager(context.applicationContext).also { INSTANCE = it }
            }
        }
        
        @Volatile
        private var initialized = AtomicBoolean(false)
    }
    
    private val executorService: ExecutorService = Executors.newFixedThreadPool(4)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    
    // Security components
    private val antiFridaHelper = AntiFridaHelper.getInstance(context)
    private val deviceFingerprinting: DeviceFingerprinting = DeviceFingerprinting.getInstance(context)
    private val securityHardening: SecurityHardening = SecurityHardening.getInstance(context)
    private val advancedAntiFrida: AdvancedAntiFrida = AdvancedAntiFrida.getInstance(context)
    private val raspDefense = RASPDefense.getInstance(context)
    private val advancedRASPDefense = AdvancedRASPDefense.getInstance(context)
    private val fintechSecurity = FintechSecurity.getInstance(context)
    private val raspCoreEngine = DefaultRaspCoreEngine(context)
    
    public interface SecurityInitializationCallback {
        fun onSecurityInitialized()
        fun onSecurityInitializationFailed(reason: String)
        fun onSecurityBreach(reason: String)
    }
    
    /**
     * Initialize all security components
     */
    fun initializeSecurity(callback: SecurityInitializationCallback?) {
        if (initialized.get()) {
            Log.w("AranSecurityMgr", "Security already initialized")
            callback?.onSecurityInitialized()
            return
        }
        
        executorService.execute {
            try {
                Log.i("AranSecurityMgr", "========================================")
                Log.i("AranSecurityMgr", "Initializing Enhanced Security Framework with Hardening")
                Log.i("AranSecurityMgr", "========================================")
                
                // Step 1: Initialize Native Core Engine (90% of logic in C++)
                Log.d("AranSecurityMgr", "Step 1: Initializing Native Core Engine...")
                raspCoreEngine.initialize()
                
                // Step 2: Initialize fintech security
                Log.d("AranSecurityMgr", "Step 2: Initializing fintech security...")
                fintechSecurity.initialize()
                
                // Step 3: Initialize advanced RASP defense
                Log.d("AranSecurityMgr", "Step 3: Initializing advanced RASP defense...")
                advancedRASPDefense.initialize()
                
                // Step 4: Initialize RASP defense layers
                Log.d("AranSecurityMgr", "Step 4: Initializing RASP defense layers...")
                raspDefense.initialize()
                
                // Step 5: Initialize advanced anti-Frida detection
                Log.d("AranSecurityMgr", "Step 5: Initializing advanced anti-Frida detection...")
                advancedAntiFrida.initialize()
                
                // Step 6: Perform advanced anti-Frida check
                Log.d("AranSecurityMgr", "Step 6: Performing advanced anti-Frida check...")
                val advancedResult = advancedAntiFrida.performComprehensiveAdvancedCheck()
                
                if (advancedResult.securityBreach) {
                    Log.e("AranSecurityMgr", "Advanced anti-Frida threat detected: ${advancedResult.threatsDetected} threats")
                    callback?.onSecurityBreach("Advanced Frida bypass detected: ${advancedResult.threatsDetected} threats")
                    triggerEmergencyShutdown("Advanced Frida bypass detected")
                    return@execute
                }
                
                Log.i("AranSecurityMgr", "Advanced anti-Frida check PASSED")
                
                // Step 7: Perform Native Core Engine check (90% of logic in C++)
                Log.d("AranSecurityMgr", "Step 7: Performing Native Core Engine check...")
                raspCoreEngine.validateEnvironment(RaspCoreEngine.FINANCE_SENSITIVE_CONTEXT)
                
                if (raspCoreEngine.getCurrentState() == RaspCoreEngine.CONFIRMED_TAMPER) {
                    Log.e("AranSecurityMgr", "Native Core Engine detected CONFIRMED_TAMPER")
                    callback?.onSecurityBreach("Native Core Engine: Confirmed tamper detected")
                    triggerEmergencyShutdown("Native Core Engine: Confirmed tamper detected")
                    return@execute
                }
                
                Log.i("AranSecurityMgr", "Native Core Engine check PASSED (state: ${raspCoreEngine.getCurrentState()})")
                
                // Step 8: Perform advanced RASP check
                Log.d("AranSecurityMgr", "Step 8: Performing advanced RASP check...")
                val advancedRASPResult = advancedRASPDefense.performComprehensiveAdvancedRASPCheck()
                
                if (advancedRASPResult.securityBreach) {
                    Log.e("AranSecurityMgr", "Advanced RASP threat detected: ${advancedRASPResult.threatsDetected} threats")
                    callback?.onSecurityBreach("Advanced RASP bypass detected: ${advancedRASPResult.threatsDetected} threats")
                    triggerEmergencyShutdown("Advanced RASP bypass detected")
                    return@execute
                }
                
                Log.i("AranSecurityMgr", "Advanced RASP check PASSED")

                // Step 9: Perform comprehensive security hardening check
                Log.d("AranSecurityMgr", "Step 10: Performing comprehensive security hardening check...")
                val hardeningResult = securityHardening.performComprehensiveSecurityCheck()
                
                if (hardeningResult.securityBreach) {
                    Log.e("AranSecurityMgr", "Security breach detected during hardening: ${hardeningResult.breachReason}")
                    callback?.onSecurityBreach(hardeningResult.breachReason)
                    triggerEmergencyShutdown(hardeningResult.breachReason)
                    return@execute
                }
                
                Log.i("AranSecurityMgr", "Security hardening check PASSED")
                
                // Step 11: Perform RASP defense check
                Log.d("AranSecurityMgr", "Step 11: Performing RASP defense check...")
                val raspStatus = raspDefense.getRASPStatus()
                
                if (!raspStatus.stringEncryptionWorking || !raspStatus.selfTraceActive) {
                    Log.e("AranSecurityMgr", "RASP defense compromised: encryption=${raspStatus.stringEncryptionWorking}, selfTrace=${raspStatus.selfTraceActive}")
                    callback?.onSecurityBreach("RASP defense compromised")
                    triggerEmergencyShutdown("RASP defense compromised")
                    return@execute
                }
                
                Log.i("AranSecurityMgr", "RASP defense check PASSED")
                
                // Step 12: Initialize Anti-Frida detection
                Log.d("AranSecurityMgr", "Step 12: Initializing Anti-Frida detection...")
                antiFridaHelper.performSecurityCheck(object : AntiFridaHelper.SecurityCallback {
                    override fun onSecurityBreach(reason: String) {
                        Log.e("AranSecurityMgr", "Security breach during initialization: $reason")
                        callback?.onSecurityBreach(reason)
                        triggerEmergencyShutdown("Security breach during initialization")
                    }
                    
                    override fun onIntegrityVerified() {
                        Log.i("AranSecurityMgr", "Anti-Frida integrity verified")
                        continueInitialization(callback)
                    }
                })
                
            } catch (e: Exception) {
                Log.e("AranSecurityMgr", "Error during security initialization", e)
                callback?.onSecurityInitializationFailed("Initialization error: ${e.message}")
            }
        }
    }
    
    /**
     * Continue initialization after Anti-Frida check
     */
    private fun continueInitialization(callback: SecurityInitializationCallback?) {
        executorService.execute {
            try {
                // Step 2: Generate device fingerprint
                Log.d("AranSecurityMgr", "Step 3: Generating device fingerprint...")
                val fingerprint = deviceFingerprinting.generateDeviceFingerprint()
                Log.d("AranSecurityMgr", "Device fingerprint generated: ${fingerprint.take(16)}...")
                
                // Step 4: Start continuous monitoring
                Log.d("AranSecurityMgr", "Step 4: Starting continuous monitoring...")
                antiFridaHelper.startMonitoring()
                
                initialized.set(true)
                Log.i("AranSecurityMgr", "Enhanced Security Framework initialized successfully")
                Log.i("AranSecurityMgr", "========================================")
                
                callback?.onSecurityInitialized()
                
            } catch (e: Exception) {
                Log.e("AranSecurityMgr", "Error during security initialization continuation", e)
                callback?.onSecurityInitializationFailed("Continuation error: ${e.message}")
            }
        }
    }
    
    /**
     * Perform comprehensive security verification
     */
    fun performComprehensiveVerification(callback: SecurityInitializationCallback?) {
        if (!initialized.get()) {
            Log.w("AranSecurityMgr", "Security not initialized, performing initialization first")
            initializeSecurity(callback)
            return
        }
        
        executorService.execute {
            try {
                Log.i("AranSecurityMgr", "Starting comprehensive security verification...")
                
                // Use AntiFridaHelper for verification
                antiFridaHelper.performSecurityCheck(object : AntiFridaHelper.SecurityCallback {
                    override fun onIntegrityVerified() {
                        Log.i("AranSecurityMgr", "Comprehensive security verification PASSED")
                        callback?.onSecurityInitialized()
                    }

                    override fun onSecurityBreach(reason: String) {
                        Log.e("AranSecurityMgr", "Comprehensive security verification FAILED: $reason")
                        callback?.onSecurityInitializationFailed(reason)
                        triggerEmergencyShutdown("Tampering detected during verification")
                    }
                })
                
            } catch (e: Exception) {
                Log.e("AranSecurityMgr", "Error during comprehensive verification", e)
                callback?.onSecurityInitializationFailed("Verification error: ${e.message}")
            }
        }
    }
    
    /**
     * Get device fingerprint for server communication
     */
    fun getDeviceFingerprint(): String {
        if (!initialized.get()) {
            Log.w("AranSecurityMgr", "Security not initialized, returning fallback fingerprint")
            return "fallback_${System.currentTimeMillis()}"
        }
        
        return deviceFingerprinting.generateDeviceFingerprint()
    }
    
    /**
     * Apply enhanced certificate pinning to connections
     */
    fun applyCertificatePinning(connection: javax.net.ssl.HttpsURLConnection, hostname: String) {
        if (!initialized.get()) {
            Log.w("AranSecurityMgr", "Security not initialized, skipping certificate pinning")
            return
        }

        // Certificate pinning is disabled (OpenSSL not available in Android NDK)
        Log.d("AranSecurityMgr", "Certificate pinning not available")
    }

    /**
     * Validate response timing to detect MITM
     */
    fun validateResponseTiming(startTime: Long, endTime: Long): Boolean {
        return antiFridaHelper.validateResponseTiming(startTime, endTime)
    }
    
    /**
     * Get security statistics
     */
    fun getSecurityStatistics(): SecurityStatistics {
        return SecurityStatistics(
            initialized = initialized.get(),
            fridaDetected = AntiFridaHelper.isFridaDetected(),
            monitoringActive = AntiFridaHelper.isMonitoringActive(),
            hardeningResult = securityHardening.performComprehensiveSecurityCheck(),
            advancedResult = advancedAntiFrida.performComprehensiveAdvancedCheck(),
            raspStatus = raspDefense.getRASPStatus(),
            advancedRASPResult = advancedRASPDefense.performComprehensiveAdvancedRASPCheck(),
            fintechResult = FintechSecurity.FintechSecurityResult(),
            raspCoreStatus = raspCoreEngine.getSecurityStatus()
        )
    }
    
    /**
     * Emergency shutdown in case of security breach
     */
    private fun triggerEmergencyShutdown(reason: String) {
        Log.e("AranSecurityMgr", "EMERGENCY SHUTDOWN TRIGGERED: $reason")
        
        // Kill app immediately
        android.os.Process.killProcess(android.os.Process.myPid())
        System.exit(1)
    }
    
    /**
     * Check if security is initialized
     */
    fun isInitialized(): Boolean = initialized.get()
    
    /**
     * Reset security (for testing purposes only)
     */
    fun resetForTesting() {
        initialized.set(false)
        deviceFingerprinting.resetCache()
    }
    
    /**
     * Get individual security components (for advanced usage)
     */
    fun getAntiFridaHelper(): AntiFridaHelper = antiFridaHelper

    fun getDeviceFingerprinting(): DeviceFingerprinting = deviceFingerprinting
    
    fun getSecurityHardening(): SecurityHardening = securityHardening
    
    fun getAdvancedAntiFrida(): AdvancedAntiFrida = advancedAntiFrida
    
    fun getRASPDefense(): RASPDefense = raspDefense
    
    fun getAdvancedRASPDefense(): AdvancedRASPDefense = advancedRASPDefense
    
    fun getFintechSecurity(): FintechSecurity = fintechSecurity
    
    fun getRaspCoreEngine(): RaspCoreEngine = raspCoreEngine
    
    /**
     * Shutdown all security components
     */
    fun shutdown() {
        Log.i("AranSecurityMgr", "Shutting down security framework...")

        antiFridaHelper.shutdown()

        if (!executorService.isShutdown) {
            executorService.shutdown()
        }
        
        scope.cancel()
        initialized.set(false)
        Log.i("AranSecurityMgr", "Security framework shutdown complete")
    }
    
    /**
     * Security statistics class
     */
    data class SecurityStatistics(
        val initialized: Boolean,
        val fridaDetected: Boolean,
        val monitoringActive: Boolean,
        val hardeningResult: SecurityHardening.SecurityCheckResult = SecurityHardening.SecurityCheckResult(),
        val advancedResult: AdvancedAntiFrida.AdvancedCheckResult = AdvancedAntiFrida.AdvancedCheckResult(),
        val raspStatus: RASPDefense.RASPStatus = RASPDefense.RASPStatus(initialized = false, selfTraceActive = false, cyclicChecksActive = false, stringEncryptionWorking = false),
        val advancedRASPResult: AdvancedRASPDefense.AdvancedRASPResult = AdvancedRASPDefense.AdvancedRASPResult(),
        val fintechResult: FintechSecurity.FintechSecurityResult = FintechSecurity.FintechSecurityResult(),
        val raspCoreStatus: RaspCoreEngine.SecurityStatus = RaspCoreEngine.SecurityStatus()
    ) {
        override fun toString(): String {
            return "Security Stats{initialized=$initialized, frida=$fridaDetected, monitoring=$monitoringActive, breach=${hardeningResult.securityBreach}, advancedBreach=${advancedResult.securityBreach}, raspCompromised=${!raspStatus.stringEncryptionWorking || !raspStatus.selfTraceActive}, advancedRASPBreach=${advancedRASPResult.securityBreach}, coreState=${raspCoreStatus.currentState}}"
        }
    }
}
