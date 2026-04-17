package org.mazhai.aran.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * AranSigil - Hardware-Backed Device Attestation Engine
 * 
 * Zero-Trust Architecture:
 * - Generates EC KeyPair in Android KeyStore (StrongBox if available)
 * - Signs attestation payloads with hardware-backed private key
 * - Creates JWT tokens bound to device TEE/StrongBox
 * - Prevents API abuse, botnets, and advanced tampering
 * 
 * Security Guarantees:
 * - Private key NEVER leaves hardware security module
 * - Signature verification proves device authenticity
 * - Payload hash prevents MITM tampering
 * - Timestamp + nonce prevent replay attacks
 */
class AranSigilEngine(private val context: Context) {

    companion object {
        private const val TAG = "AranSigilEngine"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "aran_sigil_ec_key"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val EC_CURVE = "secp256r1" // NIST P-256
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }

    init {
        ensureHardwareKeyExists()
    }

    /**
     * Ensure hardware-backed EC key exists in KeyStore
     * Uses StrongBox if available (Pixel 3+, Samsung S9+)
     */
    private fun ensureHardwareKeyExists() {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            Log.i(TAG, "Generating hardware-backed EC key...")
            generateHardwareKey()
        } else {
            Log.i(TAG, "Hardware key already exists: $KEY_ALIAS")
        }
    }

    /**
     * Generate EC KeyPair in Android KeyStore with StrongBox backing
     */
    private fun generateHardwareKey() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )

            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false) // Allow background signing
                .setInvalidatedByBiometricEnrollment(false)

            // CRITICAL: Enforce StrongBox hardware backing if available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(true)
                    Log.i(TAG, "StrongBox hardware backing enabled")
                } catch (e: Exception) {
                    Log.w(TAG, "StrongBox not available, using TEE: ${e.message}")
                }
            }

            keyPairGenerator.initialize(builder.build())
            val keyPair = keyPairGenerator.generateKeyPair()
            
            Log.i(TAG, "Hardware key generated successfully")
            Log.i(TAG, "Public Key: ${Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP).take(32)}...")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate hardware key", e)
            throw SecurityException("Hardware key generation failed", e)
        }
    }

    /**
     * Generate AranSigil JWT token
     * 
     * @param deviceFingerprint Unique device identifier
     * @param raspBitmask 12-bit RASP threat profile
     * @param payloadHash SHA-256 hash of HTTP request body
     * @param trafficSource Source of HTTP request (NATIVE_OKHTTP, WEBVIEW_FETCH, etc.)
     * @param nonce Backend-provided nonce for replay prevention
     * @return Signed JWT token
     */
    fun generateSigilToken(
        deviceFingerprint: String,
        raspBitmask: Int,
        payloadHash: String,
        trafficSource: String = "NATIVE_OKHTTP",
        nonce: String = UUID.randomUUID().toString()
    ): String {
        try {
            val timestamp = System.currentTimeMillis()

            // Build JWT claims
            val claims = JSONObject().apply {
                put("device_fingerprint", deviceFingerprint)
                put("rasp_bitmask", raspBitmask)
                put("payload_hash", payloadHash)
                put("traffic_source", trafficSource)
                put("timestamp", timestamp)
                put("nonce", nonce)
                put("iss", "aran-sigil")
                put("exp", timestamp + 300000) // 5-minute expiry
            }

            // Create JWT header
            val header = JSONObject().apply {
                put("alg", "ES256") // ECDSA with SHA-256
                put("typ", "JWT")
                put("kid", KEY_ALIAS)
            }

            // Base64URL encode header and payload
            val headerB64 = base64UrlEncode(header.toString())
            val payloadB64 = base64UrlEncode(claims.toString())
            val signingInput = "$headerB64.$payloadB64"

            // Sign with hardware-backed private key
            val signature = signWithHardwareKey(signingInput.toByteArray())
            val signatureB64 = base64UrlEncode(signature)

            val jwt = "$signingInput.$signatureB64"
            Log.i(TAG, "AranSigil token generated: ${jwt.take(50)}...")
            return jwt

        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate Sigil token", e)
            throw SecurityException("Sigil token generation failed", e)
        }
    }

    /**
     * Sign data using hardware-backed EC private key
     */
    private fun signWithHardwareKey(data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    /**
     * Get public key for backend verification
     */
    fun getPublicKey(): PublicKey {
        val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return entry.certificate.publicKey
    }

    /**
     * Get public key in Base64 format
     */
    fun getPublicKeyBase64(): String {
        return Base64.encodeToString(getPublicKey().encoded, Base64.NO_WRAP)
    }

    /**
     * Compute SHA-256 hash of HTTP request body
     */
    fun computePayloadHash(requestBody: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(requestBody.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Base64URL encoding (JWT standard)
     */
    private fun base64UrlEncode(data: String): String {
        return base64UrlEncode(data.toByteArray())
    }

    private fun base64UrlEncode(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    /**
     * Verify if key is hardware-backed (for diagnostics)
     */
    fun isHardwareBacked(): Boolean {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val factory = KeyFactory.getInstance(
                    entry.privateKey.algorithm,
                    KEYSTORE_PROVIDER
                )
                val keyInfo = factory.getKeySpec(
                    entry.privateKey,
                    android.security.keystore.KeyInfo::class.java
                )
                
                val isInsideSecureHardware = keyInfo.isInsideSecureHardware
                val isStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    keyInfo.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
                } else {
                    false
                }
                
                Log.i(TAG, "Hardware-backed: $isInsideSecureHardware, StrongBox: $isStrongBox")
                isInsideSecureHardware
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check hardware backing", e)
            false
        }
    }

    /**
     * Get device security level
     */
    fun getSecurityLevel(): String {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val factory = KeyFactory.getInstance(
                    entry.privateKey.algorithm,
                    KEYSTORE_PROVIDER
                )
                val keyInfo = factory.getKeySpec(
                    entry.privateKey,
                    android.security.keystore.KeyInfo::class.java
                )
                
                when (keyInfo.securityLevel) {
                    android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                    android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    else -> "Software"
                }
            } else {
                "TEE (Legacy)"
            }
        } catch (e: Exception) {
            "Unknown"
        }
    }
}
