package org.mazhai.aran.security

import android.content.Context
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * RaspCoreEngine - Abstract Engine Interface
 * 
 * This is the Kotlin/Java Bridge layer that acts as an Observer.
 * It doesn't know HOW checks were performed, only the Risk Score.
 * 
 * The native engine (90% of logic) performs the actual checks using:
 * - Inline Assembly
 * - Direct Syscalls
 * - State Machine for control flow flattening
 * 
 * This follows the "Native Most" architecture for 2026 Fintech security.
 */
abstract class RaspCoreEngine protected constructor(protected val context: Context) {
    
    companion object {
        const val TAG = "RaspCoreEngine"
        
        // Risk Context Constants
        const val FINANCE_SENSITIVE_CONTEXT = 1
        const val STANDARD_CONTEXT = 0
        
        // Security Result Codes (from native engine)
        const val SECURITY_OK = 0
        const val SUSPICIOUS = 1
        const val HIGHLY_SUSPICIOUS = 2
        const val CONFIRMED_TAMPER = 3
        
        // Degraded State Levels
        const val STATE_NORMAL = 0
        const val STATE_SUSPICIOUS = 1
        const val STATE_HIGHLY_SUSPICIOUS = 2
        const val STATE_CONFIRMED_TAMPER = 3
        
        @Volatile
        private var initialized = AtomicBoolean(false)
    }
    
    // Load native library
    init {
        System.loadLibrary("aran-secure")
    }
    
    // ============================================
    // Native Methods - Single Entry Point (Obfuscated)
    // ============================================
    
    /**
     * Obfuscated JNI entry point to native engine
     * Uses RegisterNatives to hide the link between Kotlin and C++
     * Method name "z9" is mapped to z9_impl in native code
     */
    protected external fun z9(riskContext: Int): Int
    
    /**
     * Obfuscated initialize method
     * Method name "a1" is mapped to a1_impl in native code
     */
    protected external fun a1()
    
    /**
     * Obfuscated shutdown method
     * Method name "b2" is mapped to b2_impl in native code
     */
    protected external fun b2()
    
    /**
     * Obfuscated detection status methods
     * Method names "c3", "d4", "e5" are mapped to corresponding implementations
     */
    protected external fun c3(): Boolean
    protected external fun d4(): Boolean
    protected external fun e5(): Boolean
    
    // ============================================
    // Public API Wrappers (for backward compatibility)
    // ============================================
    
    /**
     * Single JNI entry point to native engine
     * This is the ONLY method that communicates with the native world
     * All other checks are performed inside the native state machine
     */
    protected fun performSecurityAudit(riskContext: Int): Int {
        return z9(riskContext)
    }
    
    /**
     * Initialize native engine
     */
    protected fun initializeNative() {
        a1()
    }
    
    /**
     * Shutdown native engine
     */
    protected fun shutdownNative() {
        b2()
    }
    
    /**
     * Get detailed detection status (for debugging)
     */
    protected fun isRootDetected(): Boolean = c3()
    protected fun isFridaDetected(): Boolean = d4()
    protected fun isHooksDetected(): Boolean = e5()
    
    // ============================================
    // Degraded State Strategy
    // ============================================
    
    private var currentState = STATE_NORMAL
    
    /**
     * 2026 Fintech "Kill Switch" Strategy - Degraded State
     * 
     * Instead of hard kill (crashing the app), implement degraded states:
     * Level 1 (Suspicious): Disable Biometrics, force Password + OTP
     * Level 2 (Highly Suspicious): Disable high-value transactions (> $100)
     * Level 3 (Confirmed Tamper): Wipe local sensitive cache and logout
     */
    protected fun applyDegradedState(result: Int) {
        when (result) {
            SUSPICIOUS -> {
                currentState = STATE_SUSPICIOUS
                Log.w(TAG, "Applying Degraded State Level 1: SUSPICIOUS")
                handleSuspiciousState()
            }
            HIGHLY_SUSPICIOUS -> {
                currentState = STATE_HIGHLY_SUSPICIOUS
                Log.e(TAG, "Applying Degraded State Level 2: HIGHLY_SUSPICIOUS")
                handleHighlySuspiciousState()
            }
            CONFIRMED_TAMPER -> {
                currentState = STATE_CONFIRMED_TAMPER
                Log.e(TAG, "Applying Degraded State Level 3: CONFIRMED_TAMPER")
                handleConfirmedTamperState()
            }
            else -> {
                currentState = STATE_NORMAL
                Log.i(TAG, "State: NORMAL")
            }
        }
    }
    
    /**
     * Get current degraded state
     */
    fun getCurrentState(): Int = currentState
    
    /**
     * Check if app is in degraded state
     */
    fun isDegraded(): Boolean = currentState != STATE_NORMAL
    
    // ============================================
    // Abstract Methods - App-Specific Responses
    // ============================================
    
    /**
     * Handle Suspicious State (Level 1)
     * App-specific response: Disable Biometrics, force Password + OTP
     */
    protected abstract fun handleSuspiciousState()
    
    /**
     * Handle Highly Suspicious State (Level 2)
     * App-specific response: Disable high-value transactions (> $100)
     */
    protected abstract fun handleHighlySuspiciousState()
    
    /**
     * Handle Confirmed Tamper State (Level 3)
     * App-specific response: Wipe local sensitive cache and logout
     */
    protected abstract fun handleConfirmedTamperState()
    
    // ============================================
    // Public API - Environment Validation
    // ============================================
    
    /**
     * Validate environment using native engine
     * This is the main entry point for security validation
     */
    fun validateEnvironment(riskContext: Int = FINANCE_SENSITIVE_CONTEXT) {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting Environment Validation")
        Log.i(TAG, "Risk Context: $riskContext")
        Log.i(TAG, "========================================")
        
        // Perform security audit via native engine
        val result = performSecurityAudit(riskContext)
        
        Log.i(TAG, "Security Audit Result: $result")
        
        if (result != SECURITY_OK) {
            // Apply degraded state based on risk level
            applyDegradedState(result)
            
            // Notify app-specific handler
            handleSecurityBreach(result)
        } else {
            Log.i(TAG, "Environment validation PASSED")
        }
        
        Log.i(TAG, "========================================")
    }
    
    /**
     * Handle security breach (abstract)
     * App-specific implementation decides what to do
     */
    protected abstract fun handleSecurityBreach(errorCode: Int)
    
    // ============================================
    // Initialization & Lifecycle
    // ============================================
    
    /**
     * Initialize RaspCoreEngine
     */
    fun initialize() {
        if (initialized.get()) {
            Log.w(TAG, "RaspCoreEngine already initialized")
            return
        }
        
        Log.i(TAG, "Initializing RaspCoreEngine...")
        
        try {
            // Initialize native engine
            initializeNative()
            
            initialized.set(true)
            Log.i(TAG, "RaspCoreEngine initialized successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing RaspCoreEngine", e)
            throw e
        }
    }
    
    /**
     * Shutdown RaspCoreEngine
     */
    fun shutdown() {
        Log.i(TAG, "Shutting down RaspCoreEngine...")
        
        try {
            // Shutdown native engine
            shutdownNative()
            
            initialized.set(false)
            Log.i(TAG, "RaspCoreEngine shut down successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error shutting down RaspCoreEngine", e)
        }
    }
    
    /**
     * Check if RaspCoreEngine is initialized
     */
    fun isInitialized(): Boolean = initialized.get()
    
    /**
     * Get detailed security status (for debugging)
     */
    fun getSecurityStatus(): SecurityStatus {
        return SecurityStatus(
            rootDetected = isRootDetected(),
            fridaDetected = isFridaDetected(),
            hooksDetected = isHooksDetected(),
            currentState = currentState
        )
    }
    
    // ============================================
    // Data Classes
    // ============================================
    
    data class SecurityStatus(
        val rootDetected: Boolean = false,
        val fridaDetected: Boolean = false,
        val hooksDetected: Boolean = false,
        val currentState: Int = STATE_NORMAL
    ) {
        override fun toString(): String {
            return "SecurityStatus{root=$rootDetected, frida=$fridaDetected, hooks=$hooksDetected, state=$currentState}"
        }
    }
}

/**
 * Default implementation of RaspCoreEngine
 * Provides sensible defaults for app-specific responses
 */
class DefaultRaspCoreEngine(context: Context) : RaspCoreEngine(context) {
    
    override fun handleSuspiciousState() {
        // Level 1: Disable Biometrics, force Password + OTP
        Log.w(TAG, "Default handler: Disabling biometrics, forcing Password + OTP")
        // App can override this to implement specific behavior
    }
    
    override fun handleHighlySuspiciousState() {
        // Level 2: Disable high-value transactions (> $100)
        Log.e(TAG, "Default handler: Disabling high-value transactions")
        // App can override this to implement specific behavior
    }
    
    override fun handleConfirmedTamperState() {
        // Level 3: Wipe local sensitive cache and logout
        Log.e(TAG, "Default handler: Wiping cache and logging out")
        // App can override this to implement specific behavior
    }
    
    override fun handleSecurityBreach(errorCode: Int) {
        Log.e(TAG, "Security breach detected: $errorCode")
        // App can override this to implement specific behavior
    }
}
