package org.mazhai.aran.security

import android.content.Context
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Advanced Anti-Frida Detection using Native Defensive Patterns
 * Implements layered native defensive patterns to bypass Frida hooking
 */
class AdvancedAntiFrida private constructor(private val context: Context) {
    
    companion object {
        @Volatile
        private var INSTANCE: AdvancedAntiFrida? = null
        
        fun getInstance(context: Context): AdvancedAntiFrida {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AdvancedAntiFrida(context.applicationContext).also { INSTANCE = it }
            }
        }
        
        // Load native library
        init {
            System.loadLibrary("aran-secure")
        }
        
        @Volatile
        private var initialized = AtomicBoolean(false)
        @Volatile
        private var memoryStateInitialized = AtomicBoolean(false)
        @Volatile
        private var baselineTimingInitialized = AtomicBoolean(false)
    }
    
    // ============================================
    // Native Method Declarations
    // ============================================
    
    private external fun initializeDirectSyscalls()
    private external fun checkMapsDirectSyscall(): Boolean
    private external fun checkFunctionsHooked(): Boolean
    private external fun initializeMemoryState()
    private external fun checkMemoryIntegrity(): Boolean
    private external fun initializeBaselineTiming()
    private external fun checkTimingDeviation(): Boolean
    private external fun scanFridaPipes(): Boolean
    private external fun scanFridaNetwork(): Boolean
    private external fun performAdvancedCheck(): Boolean
    
    // ============================================
    // Public API
    // ============================================
    
    /**
     * Initialize all advanced detection systems
     * Must be called at app startup
     */
    fun initialize() {
        if (initialized.get()) {
            Log.w("AdvancedAntiFrida", "Already initialized")
            return
        }
        
        Log.i("AdvancedAntiFrida", "Initializing advanced anti-Frida detection...")
        
        try {
            // Initialize direct syscalls
            initializeDirectSyscalls()
            Log.i("AdvancedAntiFrida", "Direct syscalls initialized")
            
            // Initialize memory state (for integrity checking)
            initializeMemoryStateNative()
            Log.i("AdvancedAntiFrida", "Memory state initialized")
            
            // Initialize baseline timing
            initializeBaselineTimingNative()
            Log.i("AdvancedAntiFrida", "Baseline timing initialized")
            
            initialized.set(true)
            Log.i("AdvancedAntiFrida", "Advanced anti-Frida detection initialized successfully")
            
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error initializing advanced detection", e)
        }
    }
    
    /**
     * Check /proc/self/maps using direct syscalls
     * Bypasses Frida's strstr hooking in libc
     */
    fun checkMapsUsingDirectSyscalls(): Boolean {
        if (!initialized.get()) {
            Log.w("AdvancedAntiFrida", "Not initialized, initializing now")
            initialize()
        }
        
        return try {
            val result = checkMapsDirectSyscall()
            Log.d("AdvancedAntiFrida", "Direct syscall maps check: ${if (result) "THREAT" else "CLEAR"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error checking maps with direct syscalls", e)
            false
        }
    }
    
    /**
     * Check for hooked functions by examining trampolines
     * Detects if libc functions have been hooked by Frida
     */
    fun checkForHookedFunctions(): Boolean {
        if (!initialized.get()) {
            Log.w("AdvancedAntiFrida", "Not initialized, initializing now")
            initialize()
        }
        
        return try {
            val result = checkFunctionsHooked()
            Log.d("AdvancedAntiFrida", "Function hooking check: ${if (result) "THREAT" else "CLEAR"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error checking for hooked functions", e)
            false
        }
    }
    
    /**
     * Initialize memory state for integrity checking
     * Stores baseline checksum and segment counts
     */
    fun initializeMemoryStateNative() {
        try {
            initializeMemoryState()
            memoryStateInitialized.set(true)
            Log.i("AdvancedAntiFrida", "Memory state initialized successfully")
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error initializing memory state", e)
        }
    }
    
    /**
     * Check memory integrity
     * Detects library injection by comparing current state to baseline
     */
    fun checkMemoryIntegrityNative(): Boolean {
        if (!memoryStateInitialized.get()) {
            Log.w("AdvancedAntiFrida", "Memory state not initialized, initializing now")
            initializeMemoryStateNative()
        }
        
        return try {
            val result = checkMemoryIntegrity()
            Log.d("AdvancedAntiFrida", "Memory integrity check: ${if (result) "COMPROMISED" else "OK"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error checking memory integrity", e)
            false
        }
    }
    
    /**
     * Initialize baseline timing
     * Stores baseline execution time for simple operations
     */
    fun initializeBaselineTimingNative() {
        try {
            initializeBaselineTiming()
            baselineTimingInitialized.set(true)
            Log.i("AdvancedAntiFrida", "Baseline timing initialized successfully")
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error initializing baseline timing", e)
        }
    }
    
    /**
     * Check for timing deviation
     * Detects instrumentation by measuring execution time overhead
     */
    fun checkTimingDeviationNative(): Boolean {
        if (!baselineTimingInitialized.get()) {
            Log.w("AdvancedAntiFrida", "Baseline timing not initialized, initializing now")
            initializeBaselineTimingNative()
        }
        
        return try {
            val result = checkTimingDeviation()
            Log.d("AdvancedAntiFrida", "Timing deviation check: ${if (result) "ANOMALY" else "NORMAL"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error checking timing deviation", e)
            false
        }
    }
    
    /**
     * Scan for Frida named pipes
     * Detects Frida artifacts in the file system
     */
    fun scanForFridaPipes(): Boolean {
        return try {
            val result = scanFridaPipes()
            Log.d("AdvancedAntiFrida", "Frida pipes scan: ${if (result) "DETECTED" else "CLEAR"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error scanning for Frida pipes", e)
            false
        }
    }
    
    /**
     * Scan for Frida network connections
     * Detects Frida network artifacts (port 27042)
     */
    fun scanForFridaNetwork(): Boolean {
        return try {
            val result = scanFridaNetwork()
            Log.d("AdvancedAntiFrida", "Frida network scan: ${if (result) "DETECTED" else "CLEAR"}")
            result
        } catch (e: Exception) {
            Log.e("AdvancedAntiFrida", "Error scanning for Frida network", e)
            false
        }
    }
    
    /**
     * Perform comprehensive advanced check
     * Runs all advanced detection patterns
     */
    fun performComprehensiveAdvancedCheck(): AdvancedCheckResult {
        Log.i("AdvancedAntiFrida", "========================================")
        Log.i("AdvancedAntiFrida", "Starting Comprehensive Advanced Check")
        Log.i("AdvancedAntiFrida", "========================================")
        
        val result = AdvancedCheckResult()
        
        // Check 1: Direct syscall maps scan
        Log.d("AdvancedAntiFrida", "Check 1: Direct syscall maps scan...")
        result.mapsDirectSyscallThreat = checkMapsUsingDirectSyscalls()
        
        // Check 2: Function hooking
        Log.d("AdvancedAntiFrida", "Check 2: Function hooking...")
        result.functionsHooked = checkForHookedFunctions()
        
        // Check 3: Memory integrity
        Log.d("AdvancedAntiFrida", "Check 3: Memory integrity...")
        result.memoryIntegrityCompromised = checkMemoryIntegrityNative()
        
        // Check 4: Timing deviation
        Log.d("AdvancedAntiFrida", "Check 4: Timing deviation...")
        result.timingAnomaly = checkTimingDeviationNative()
        
        // Check 5: Frida pipes
        Log.d("AdvancedAntiFrida", "Check 5: Frida pipes...")
        result.fridaPipesDetected = scanForFridaPipes()
        
        // Check 6: Frida network
        Log.d("AdvancedAntiFrida", "Check 6: Frida network...")
        result.fridaNetworkDetected = scanForFridaNetwork()
        
        // Check 7: Native comprehensive check
        Log.d("AdvancedAntiFrida", "Check 7: Native comprehensive check...")
        result.nativeThreatDetected = performAdvancedCheck()
        
        // Calculate overall threat level
        result.threatsDetected = listOf(
            result.mapsDirectSyscallThreat,
            result.functionsHooked,
            result.memoryIntegrityCompromised,
            result.timingAnomaly,
            result.fridaPipesDetected,
            result.fridaNetworkDetected,
            result.nativeThreatDetected
        ).count { it }
        
        result.securityBreach = result.threatsDetected > 0
        
        Log.i("AdvancedAntiFrida", "========================================")
        Log.i("AdvancedAntiFrida", "Advanced check complete")
        Log.i("AdvancedAntiFrida", "Threats detected: ${result.threatsDetected}")
        Log.i("AdvancedAntiFrida", "Security breach: ${result.securityBreach}")
        Log.i("AdvancedAntiFrida", "========================================")
        
        return result
    }
    
    /**
     * Check if advanced detection is initialized
     */
    fun isInitialized(): Boolean = initialized.get()
    
    /**
     * Reset initialization state (for testing)
     */
    fun reset() {
        initialized.set(false)
        memoryStateInitialized.set(false)
        baselineTimingInitialized.set(false)
    }
    
    /**
     * Advanced check result data class
     */
    data class AdvancedCheckResult(
        var securityBreach: Boolean = false,
        var threatsDetected: Int = 0,
        var mapsDirectSyscallThreat: Boolean = false,
        var functionsHooked: Boolean = false,
        var memoryIntegrityCompromised: Boolean = false,
        var timingAnomaly: Boolean = false,
        var fridaPipesDetected: Boolean = false,
        var fridaNetworkDetected: Boolean = false,
        var nativeThreatDetected: Boolean = false
    ) {
        override fun toString(): String {
            return """AdvancedCheckResult {
                securityBreach=$securityBreach,
                threatsDetected=$threatsDetected,
                mapsDirectSyscallThreat=$mapsDirectSyscallThreat,
                functionsHooked=$functionsHooked,
                memoryIntegrityCompromised=$memoryIntegrityCompromised,
                timingAnomaly=$timingAnomaly,
                fridaPipesDetected=$fridaPipesDetected,
                fridaNetworkDetected=$fridaNetworkDetected,
                nativeThreatDetected=$nativeThreatDetected
            }""".trimIndent()
        }
    }
}
