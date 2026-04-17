package org.mazhai.aran.omninet

import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import org.mazhai.aran.security.AranSigilEngine
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * AranOmniNet JavaScript Bridge
 *
 * Security Features:
 * - Synchronous Sigil generation from JavaScript
 * - Payload hash computation
 * - Public key retrieval
 * - Traffic source tracking
 * - Short-lived single-use bridge tokens: JS must call acquireBridgeToken()
 *   and present a valid, unexpired, unused token on every sensitive call.
 *   Tokens expire after TOKEN_TTL_MS and are consumed on first use.
 */
class AranJSBridge(
    private val sigilEngine: AranSigilEngine,
    private val getRaspBitmask: () -> Int,
    private val getDeviceFingerprint: () -> String
) {

    companion object {
        private const val TAG = "AranJSBridge"
        private const val TOKEN_TTL_MS = 30_000L
        private const val TOKEN_BYTES = 24
    }

    private data class TokenEntry(val issuedAt: Long)
    private val tokenStore = ConcurrentHashMap<String, TokenEntry>()
    private val secureRandom = SecureRandom()

    private fun issueToken(): String {
        val raw = ByteArray(TOKEN_BYTES).also { secureRandom.nextBytes(it) }
        val token = Base64.encodeToString(raw, Base64.NO_WRAP or Base64.URL_SAFE)
        tokenStore[token] = TokenEntry(issuedAt = System.currentTimeMillis())
        purgeExpiredTokens()
        return token
    }

    private fun consumeToken(token: String): Boolean {
        val entry = tokenStore.remove(token) ?: return false
        return (System.currentTimeMillis() - entry.issuedAt) < TOKEN_TTL_MS
    }

    private fun purgeExpiredTokens() {
        val now = System.currentTimeMillis()
        tokenStore.entries.removeIf { (_, v) -> (now - v.issuedAt) >= TOKEN_TTL_MS }
    }

    /**
     * Issue a short-lived single-use bridge token to JavaScript.
     * JS must call this before any sensitive bridge method and pass
     * the returned token as the first argument. Tokens expire after
     * 30 seconds and are consumed (invalidated) on first use.
     *
     * @return Base64-URL encoded 24-byte random token
     */
    @JavascriptInterface
    fun acquireBridgeToken(): String {
        return try {
            issueToken()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to issue bridge token", e)
            ""
        }
    }

    /**
     * Generate hardware-signed Sigil token from JavaScript.
     * Requires a valid bridge token issued by acquireBridgeToken().
     *
     * @param bridgeToken Single-use token from acquireBridgeToken()
     * @param payloadHash SHA-256 hash of request body (computed in JS)
     * @param trafficSource Source of the HTTP request (WEBVIEW_FETCH, WEBVIEW_XHR, etc.)
     * @return JWT token signed with Android KeyStore private key, or empty string on auth failure
     */
    @JavascriptInterface
    fun getSigil(bridgeToken: String, payloadHash: String, trafficSource: String): String {
        if (!consumeToken(bridgeToken)) {
            Log.e(TAG, "Bridge token invalid or expired for getSigil — possible JS bridge hijack")
            return ""
        }
        return try {
            val raspBitmask = getRaspBitmask()
            val deviceFingerprint = getDeviceFingerprint()
            sigilEngine.generateSigilToken(
                deviceFingerprint = deviceFingerprint,
                raspBitmask = raspBitmask,
                payloadHash = payloadHash,
                trafficSource = trafficSource
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate Sigil from JavaScript", e)
            ""
        }
    }

    /**
     * Compute SHA-256 hash of request body
     * 
     * @param body Request body string
     * @return Base64-encoded SHA-256 hash
     */
    @JavascriptInterface
    fun computePayloadHash(body: String): String {
        return try {
            sigilEngine.computePayloadHash(body)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to compute payload hash", e)
            ""
        }
    }

    /**
     * Get public key for backend verification
     * 
     * @return Base64-encoded EC public key
     */
    @JavascriptInterface
    fun getPublicKey(): String {
        return try {
            sigilEngine.getPublicKeyBase64()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get public key", e)
            ""
        }
    }

    /**
     * Get security level for diagnostics
     * 
     * @return "StrongBox", "TEE", or "Software"
     */
    @JavascriptInterface
    fun getSecurityLevel(): String {
        return sigilEngine.getSecurityLevel()
    }

    /**
     * Check if hardware-backed
     * 
     * @return true if key is in hardware security module
     */
    @JavascriptInterface
    fun isHardwareBacked(): Boolean {
        return sigilEngine.isHardwareBacked()
    }
}
