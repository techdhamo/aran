package org.mazhai.aran

/**
 * AranThreatListener - Native Callback Interface
 * 
 * Allows host applications to intercept threat detection events
 * and implement custom UI/UX responses.
 * 
 * This is triggered when the tenant's reaction policy is set to CUSTOM.
 * 
 * Usage:
 * ```kotlin
 * AranSecure.start(
 *     context = this,
 *     licenseKey = "YOUR_LICENSE",
 *     environment = AranEnvironment.RELEASE,
 *     listener = object : AranThreatListener {
 *         override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
 *             // Custom threat handling
 *             showCustomSecurityWarning(status)
 *         }
 *     }
 * )
 * ```
 */
interface AranThreatListener {
    /**
     * Called when a threat is detected and the reaction policy is CUSTOM
     * 
     * @param status Complete device security status with all threat flags
     * @param reactionPolicy The configured reaction policy (will be "CUSTOM")
     */
    fun onThreatDetected(status: DeviceStatus, reactionPolicy: String)
}
