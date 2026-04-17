@file:OptIn(ExperimentalStdlibApi::class)

package org.mazhai.aran.security

import android.content.Context
import android.os.Handler
import android.os.Build
import android.os.Looper
import android.util.Log
import java.io.File
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.Path
import kotlin.io.path.exists
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AntiFridaHelper private constructor(private val context: Context) {
    
    companion object {
        @Volatile
        private var INSTANCE: AntiFridaHelper? = null
        
        fun getInstance(context: Context): AntiFridaHelper {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AntiFridaHelper(context.applicationContext).also { INSTANCE = it }
            }
        }
        
        @Volatile
        private var fridaDetected = false
        
        @Volatile
        private var monitoringActive = false
        
        fun isFridaDetected(): Boolean = fridaDetected
        fun isMonitoringActive(): Boolean = monitoringActive
        
        // Load native library
        init {
            System.loadLibrary("aran-secure")
        }
    }
    
    private val executorService: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler: Handler = Handler(Looper.getMainLooper())
    
    interface SecurityCallback {
        fun onSecurityBreach(reason: String)
        fun onIntegrityVerified()
    }
    
    /**
     * Comprehensive anti-Frida detection
     */
    external fun detectFrida(): Boolean
    
    /**
     * Start continuous background monitoring
     */
    external fun startMonitoring()
    
    /**
     * Get unique device fingerprint
     */
    external fun getDeviceFingerprint(): String
    
    /**
     * Verify app integrity
     */
    external fun verifyAppIntegrity(): Boolean
    
    /**
     * Run comprehensive security check
     */
    fun performSecurityCheck(callback: SecurityCallback) {
        executorService.execute {
            try {
                Log.i("AranAntiFrida", "Starting comprehensive security check...")
                
                // 1. Native anti-Frida detection
                Log.d("AranAntiFrida", "Running native anti-Frida detection...")
                val fridaDetectedNative = detectFrida()
                
                if (fridaDetectedNative) {
                    Log.e("AranAntiFrida", "NATIVE FRIDA DETECTION TRIGGERED")
                    notifySecurityBreach(callback, "Frida instrumentation detected via native analysis")
                    return@execute
                }
                
                // 2. Java-level checks
                Log.d("AranAntiFrida", "Running Java-level security checks...")
                if (performJavaSecurityChecks()) {
                    notifySecurityBreach(callback, "Security violation detected via Java analysis")
                    return@execute
                }
                
                // 3. App integrity verification
                Log.d("AranAntiFrida", "Verifying app integrity...")
                if (!verifyAppIntegrity()) {
                    notifySecurityBreach(callback, "App integrity verification failed")
                    return@execute
                }
                
                // 4. Device fingerprint validation
                Log.d("AranAntiFrida", "Generating device fingerprint...")
                val fingerprint = getDeviceFingerprint()
                Log.d("AranAntiFrida", "Device fingerprint: ${fingerprint.take(20)}...")
                
                // 5. Start continuous monitoring if not already active
                if (!monitoringActive) {
                    Log.d("AranAntiFrida", "Starting continuous monitoring...")
                    startMonitoring()
                    monitoringActive = true
                }
                
                Log.i("AranAntiFrida", "All security checks PASSED")
                notifyIntegrityVerified(callback)
                
            } catch (e: Exception) {
                Log.e("AranAntiFrida", "Security check failed with exception", e)
                notifySecurityBreach(callback, "Security check exception: ${e.message}")
            }
        }
    }
    
    /**
     * Java-level security checks
     */
    private fun performJavaSecurityChecks(): Boolean {
        Log.d("AranAntiFrida", "Performing Java-level security checks...")
        
        // Check for common debugging flags
        if (android.os.Build.TAGS != null && android.os.Build.TAGS.contains("test-keys")) {
            Log.e("AranAntiFrida", "Test-keys detected in build tags")
            return true
        }
        
        // Check for debugging properties using reflection
        try {
            val systemPropertiesClass = Class.forName("android.os.SystemProperties")
            val getIntMethod = systemPropertiesClass.getMethod("getInt", String::class.java, Int::class.javaPrimitiveType)
            val isDebuggable = getIntMethod.invoke(null, "ro.debuggable", 0) as Int
            if (isDebuggable == 1) {
                Log.e("AranAntiFrida", "Debuggable build detected")
                return true
            }
        } catch (e: Exception) {
            Log.w("AranAntiFrida", "Could not check debuggable property", e)
        }
        
        // Check for emulator
        if (isEmulator()) {
            Log.e("AranAntiFrida", "Emulator environment detected")
            return true
        }
        
        // Check for hooking frameworks
        if (detectHookingFrameworks()) {
            Log.e("AranAntiFrida", "Hooking framework detected")
            return true
        }
        
        // Check for suspicious processes
        if (detectSuspiciousProcesses()) {
            Log.e("AranAntiFrida", "Suspicious processes detected")
            return true
        }
        
        return false
    }
    
    /**
     * Detect if running in emulator
     */
    private fun isEmulator(): Boolean {
        return (android.os.Build.FINGERPRINT.startsWith("generic") ||
                android.os.Build.FINGERPRINT.lowercase().contains("vbox") ||
                android.os.Build.FINGERPRINT.lowercase().contains("test-keys") ||
                android.os.Build.MODEL.contains("google_sdk") ||
                android.os.Build.MODEL.contains("Emulator") ||
                android.os.Build.MODEL.contains("Android SDK built for x86") ||
                android.os.Build.MANUFACTURER.contains("Genymotion") ||
                (android.os.Build.BRAND.startsWith("generic") && android.os.Build.DEVICE.startsWith("generic")) ||
                "google_sdk" == android.os.Build.PRODUCT)
    }
    
    /**
     * Detect hooking frameworks
     */
    private fun detectHookingFrameworks(): Boolean {
        try {
            // Check for Xposed
            val xposedClass = Class.forName("de.robv.android.xposed.XposedBridge")
            if (xposedClass != null) {
                Log.e("AranAntiFrida", "Xposed framework detected")
                return true
            }
        } catch (e: ClassNotFoundException) {
            // Expected if Xposed is not present
        }
        
        try {
            // Check for Cydia Substrate
            val substrateClass = Class.forName("com.saurik.substrate.MS")
            if (substrateClass != null) {
                Log.e("AranAntiFrida", "Cydia Substrate detected")
                return true
            }
        } catch (e: ClassNotFoundException) {
            // Expected if Substrate is not present
        }
        
        // Check for Frida via Java reflection
        try {
            Class.forName("frida.Frida")
            Log.e("AranAntiFrida", "Frida Java API detected")
            return true
        } catch (e: ClassNotFoundException) {
            // Expected if Frida is not present
        }
        
        return false
    }
    
    /**
     * Detect suspicious processes
     */
    private fun detectSuspiciousProcesses(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("ps")
            val reader = java.io.BufferedReader(
                java.io.InputStreamReader(process.inputStream))
            
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val lowerLine = line!!.lowercase()
                if (lowerLine.contains("frida") || lowerLine.contains("gum") || 
                    lowerLine.contains("objection") || lowerLine.contains("drozer")) {
                    Log.e("AranAntiFrida", "Suspicious process detected: $line")
                    return true
                }
            }
            reader.close()
            process.destroy()
        } catch (e: Exception) {
            Log.w("AranAntiFrida", "Failed to check processes: ${e.message}")
        }
        
        return false
    }
    
    /**
     * Generate secure nonce for integrity verification
     */
    fun generateSecureNonce(): String {
        val random = SecureRandom()
        val nonceBytes = ByteArray(32)
        random.nextBytes(nonceBytes)
        
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(nonceBytes)
            android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("AranAntiFrida", "Failed to generate nonce", e)
            random.nextLong().toHexString()
        }
    }
    
    /**
     * Validate response timing to detect MITM
     */
    fun validateResponseTiming(startTime: Long, endTime: Long): Boolean {
        val duration = endTime - startTime
        
        // If response is too fast (< 50ms) or too slow (> 10 seconds), suspicious
        if (duration < 50 || duration > 10000) {
            Log.w("AranAntiFrida", "Suspicious response timing: ${duration}ms")
            return false
        }
        
        return true
    }
    
    /**
     * Enhanced certificate pinning validation
     */
    fun validateCertificatePinning(hostname: String, certs: Array<java.security.cert.Certificate>): Boolean {
        if (certs.isEmpty()) {
            Log.e("AranAntiFrida", "No certificates provided for validation")
            return false
        }
        
        try {
            // Validate hostname
            if (!hostname.equals("api.dhamo.in") && !hostname.equals("api2.dhamo.in")) {
                Log.e("AranAntiFrida", "Invalid hostname for certificate pinning: $hostname")
                return false
            }
            
            // Calculate certificate pins
            val digest = MessageDigest.getInstance("SHA-256")
            for (cert in certs) {
                if (cert is java.security.cert.X509Certificate) {
                    val publicKey = cert.publicKey.encoded
                    val hash = digest.digest(publicKey)
                    val pin = "sha256/${android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)}"
                    
                    Log.d("AranAntiFrida", "Certificate pin: $pin")
                    
                    // Expected pin for api.dhamo.in (should be updated with actual certificate)
                    val expectedPin = "sha256/raNsyIdcz+Lzp5xP7h+LccrnEnkVG4lyHdvMemhlZWI="
                    if (pin == expectedPin) {
                        Log.i("AranAntiFrida", "Certificate pin validation PASSED")
                        return true
                    }
                }
            }
            
            Log.e("AranAntiFrida", "Certificate pin validation FAILED - no matching pins found")
            return false
            
        } catch (e: Exception) {
            Log.e("AranAntiFrida", "Certificate validation error", e)
            return false
        }
    }
    
    /**
     * Trigger immediate security response
     */
    fun triggerSecurityResponse(reason: String) {
        Log.e("AranAntiFrida", "SECURITY BREACH TRIGGERED: $reason")
        fridaDetected = true
        
        // Kill app immediately
        android.os.Process.killProcess(android.os.Process.myPid())
        System.exit(1)
    }
    
    private fun notifySecurityBreach(callback: SecurityCallback, reason: String) {
        fridaDetected = true
        mainHandler.post { callback.onSecurityBreach(reason) }
    }
    
    private fun notifyIntegrityVerified(callback: SecurityCallback) {
        mainHandler.post { callback.onIntegrityVerified() }
    }
    
    fun shutdown() {
        if (!executorService.isShutdown) {
            executorService.shutdown()
        }
    }
}
