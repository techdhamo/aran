package org.mazhai.aran.security

import android.content.Context
import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import java.io.IOException

/**
 * AranSigil OkHttp Interceptor
 * 
 * Automatically attaches hardware-backed attestation tokens to outbound API requests.
 * 
 * Usage (Fintech Client Integration):
 * ```kotlin
 * val okHttpClient = OkHttpClient.Builder()
 *     .addInterceptor(AranSigilInterceptor(context, aranSecure))
 *     .build()
 * 
 * // All API calls now include X-Aran-Sigil header
 * val retrofit = Retrofit.Builder()
 *     .client(okHttpClient)
 *     .build()
 * ```
 * 
 * Security Features:
 * - Automatic JWT signing with hardware private key
 * - Payload hash prevents MITM tampering
 * - RASP bitmask included for device posture validation
 * - Zero-configuration for fintech developers
 */
class AranSigilInterceptor(
    private val context: Context,
    private val getRaspBitmask: () -> Int,
    private val getDeviceFingerprint: () -> String
) : Interceptor {

    companion object {
        private const val TAG = "AranSigilInterceptor"
        private const val HEADER_SIGIL = "X-Aran-Sigil"
        private const val HEADER_PUBLIC_KEY = "X-Aran-Public-Key"
    }

    private val sigilEngine = AranSigilEngine(context)

    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()

        // Skip Sigil for non-business API calls (e.g., Aran's own sync endpoints)
        if (shouldSkipSigil(originalRequest.url.toString())) {
            Log.d(TAG, "Skipping Sigil for internal endpoint: ${originalRequest.url}")
            return chain.proceed(originalRequest)
        }

        try {
            // Extract request body for payload hash
            val requestBody = originalRequest.body
            val payloadHash = if (requestBody != null) {
                val buffer = Buffer()
                requestBody.writeTo(buffer)
                val bodyString = buffer.readUtf8()
                sigilEngine.computePayloadHash(bodyString)
            } else {
                sigilEngine.computePayloadHash("") // Empty body
            }

            // Get current RASP bitmask and device fingerprint
            val raspBitmask = getRaspBitmask()
            val deviceFingerprint = getDeviceFingerprint()

            // Generate AranSigil JWT token
            val sigilToken = sigilEngine.generateSigilToken(
                deviceFingerprint = deviceFingerprint,
                raspBitmask = raspBitmask,
                payloadHash = payloadHash
            )

            // Attach Sigil and Public Key to request headers
            val modifiedRequest = originalRequest.newBuilder()
                .header(HEADER_SIGIL, sigilToken)
                .header(HEADER_PUBLIC_KEY, sigilEngine.getPublicKeyBase64())
                .build()

            Log.i(TAG, "AranSigil attached to request: ${originalRequest.url}")
            Log.d(TAG, "RASP Bitmask: $raspBitmask, Security Level: ${sigilEngine.getSecurityLevel()}")

            return chain.proceed(modifiedRequest)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to attach AranSigil", e)
            // Fail-open or fail-closed based on security policy
            // For maximum security, fail-closed (block request)
            throw IOException("AranSigil generation failed - request blocked", e)
        }
    }

    /**
     * Skip Sigil for Aran's internal endpoints to avoid circular dependencies
     */
    private fun shouldSkipSigil(url: String): Boolean {
        return url.contains("/api/v1/config/sync") ||
               url.contains("/api/v1/telemetry/ingest") ||
               url.contains("/api/v1/attest")
    }
}

/**
 * Convenience factory for AranSecure integration
 */
fun createAranSigilInterceptor(
    context: Context,
    aranSecure: org.mazhai.aran.AranSecure
): AranSigilInterceptor {
    return AranSigilInterceptor(
        context = context,
        getRaspBitmask = { aranSecure.getEnvironment().bitmask },
        getDeviceFingerprint = { aranSecure.getDeviceFingerprint() }
    )
}
