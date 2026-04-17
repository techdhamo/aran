/**
 * ANDROID NATIVE MODULE FOR ARAN RASP ENGINE
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 */

package com.aran.security.rasp;

public class RASPNativeModule {
    static {
        System.loadLibrary("aran_rasp");
    }

    // ============================================
    // NATIVE METHOD DECLARATIONS
    // ============================================

    /**
     * Execute security audit
     * @param selector Obfuscated selector value
     * @return Audit result
     */
    public native int executeAudit(int selector);

    /**
     * Get detection status
     * @param statusType Obfuscated status type value
     * @return Status result
     */
    public native int getStatus(int statusType);

    /**
     * Initialize RASP engine
     */
    public native void initialize();

    /**
     * Shutdown RASP engine
     */
    public native void shutdown();

    // ============================================
    // PUBLIC API
    // ============================================

    /**
     * Execute security audit with silent failure
     * @param selector Obfuscated selector value
     * @return Audit result or 0x7F3D on failure
     */
    public int executeAuditSafe(int selector) {
        try {
            return executeAudit(selector);
        } catch (Exception e) {
            return 0x7F3D; // Security OK (silent failure)
        }
    }

    /**
     * Get detection status with silent failure
     * @param statusType Obfuscated status type value
     * @return Status result or 0 on failure
     */
    public int getStatusSafe(int statusType) {
        try {
            return getStatus(statusType);
        } catch (Exception e) {
            return 0; // Silent failure
        }
    }

    /**
     * Initialize RASP engine with silent failure
     */
    public void initializeSafe() {
        try {
            initialize();
        } catch (Exception e) {
            // Silent failure
        }
    }

    /**
     * Shutdown RASP engine with silent failure
     */
    public void shutdownSafe() {
        try {
            shutdown();
        } catch (Exception e) {
            // Silent failure
        }
    }
}
