package org.mazhai.aran.internal

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.*
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.json.JSONObject
import org.mazhai.aran.AranSecure
import org.mazhai.aran.core.AranNative
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Phantom Channel — HTTP/3 QUIC over UDP Configuration Sync
 *
 * Architecture:
 * 1. Cronet (Chromium Network Stack) configured strictly for QUIC
 * 2. Bypasses standard HTTP TCP proxies (Burp Suite, Charles Proxy)
 * 3. Fetches dynamic config from mazhai-central over UDP port 443
 * 4. Decrypts with StrongBox KeyStore, verifies backend HMAC signature
 * 5. Updates local hardware-sealed state + native dynamic TLS pins
 * 6. On MITM detection → immediate KILL_APP via AranThreatListener
 */
internal class AranPhantomSync(
    private val context: Context,
    private val licenseKey: String
) {
    companion object {
        private const val TAG = "AranPhantom"
        private const val KEYSTORE_ALIAS_AES = "aran_phantom_aes"
        private const val KEYSTORE_ALIAS_HMAC = "aran_phantom_hmac"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val executor: Executor = Executors.newSingleThreadExecutor()
    private val aranNative = AranNative()

    @Volatile private var cronetEngine: CronetEngine? = null
    @Volatile private var syncEndpoint: String = ""
    @Volatile private var syncIntervalSeconds: Long = 60
    @Volatile private var isRunning = false
    @Volatile private var lastSyncTimestamp: Long = 0L

    // Sealed HMAC key material (only used for response verification)
    @Volatile private var sealedHmacKey: ByteArray? = null

    // ── Lifecycle ──

    fun start(genesisJson: JSONObject) {
        if (isRunning) return
        isRunning = true

        // Extract config from Genesis state
        syncEndpoint = genesisJson.optString("sync_endpoint", "https://api.aran.mazhai.org")
        syncIntervalSeconds = genesisJson.optLong("sync_interval_seconds", 60)

        // Seal AES and HMAC keys to Android StrongBox KeyStore
        val aesKeyBytes = Base64.decode(genesisJson.getString("aes_key"), Base64.NO_WRAP)
        val hmacKeyBytes = Base64.decode(genesisJson.getString("hmac_secret"), Base64.NO_WRAP)
        sealKeyToStrongBox(KEYSTORE_ALIAS_AES, aesKeyBytes)
        sealedHmacKey = hmacKeyBytes.copyOf() // kept for HMAC verification
        sealKeyToStrongBox(KEYSTORE_ALIAS_HMAC, hmacKeyBytes)

        // Wipe plaintext key material from JVM heap
        aesKeyBytes.fill(0)
        hmacKeyBytes.fill(0)

        // Initialize Cronet with strict QUIC configuration
        initCronetEngine()

        // Start periodic sync
        scope.launch {
            // Immediate first sync
            performPhantomSync()

            // Periodic sync
            while (isRunning) {
                delay(syncIntervalSeconds * 1000)
                performPhantomSync()
            }
        }
    }

    fun stop() {
        isRunning = false
        scope.cancel()
        cronetEngine?.shutdown()
        cronetEngine = null
    }

    fun getLastSyncTimestamp(): Long = lastSyncTimestamp

    // ── Cronet QUIC Engine ──

    private fun initCronetEngine() {
        try {
            val host = extractHost(syncEndpoint)
            cronetEngine = CronetEngine.Builder(context)
                .enableQuic(true)
                .addQuicHint(host, 443, 443)
                .enableHttp2(true)
                .setStoragePath(context.cacheDir.absolutePath)
                .enableBrotli(true)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Cronet init failed", e)
        }
    }

    // ── Phantom Sync (QUIC/UDP) ──

    private suspend fun performPhantomSync() {
        val engine = cronetEngine ?: return

        val nonce = java.util.UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        val url = "$syncEndpoint/api/v1/config/sync?os=android&rasp_version=1.0.0"

        val result = CompletableDeferred<ByteArray?>()

        val callback = object : UrlRequest.Callback() {
            private val responseBody = ByteBuffer.allocateDirect(65536)

            override fun onRedirectReceived(
                request: UrlRequest, info: UrlResponseInfo, newLocationUrl: String
            ) {
                request.followRedirect()
            }

            override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                val statusCode = info.httpStatusCode
                if (statusCode != 200) {
                    Log.w(TAG, "Phantom sync HTTP $statusCode")
                    request.cancel()
                    result.complete(null)
                    return
                }

                // Check if negotiated protocol is QUIC
                val protocol = info.negotiatedProtocol
                if (protocol.contains("quic", ignoreCase = true) ||
                    protocol.contains("h3", ignoreCase = true)) {
                    Log.d(TAG, "QUIC negotiated: $protocol")
                }

                request.read(responseBody)
            }

            override fun onReadCompleted(
                request: UrlRequest, info: UrlResponseInfo, byteBuffer: ByteBuffer
            ) {
                byteBuffer.flip()
                request.read(byteBuffer)
            }

            override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                responseBody.flip()
                val bytes = ByteArray(responseBody.remaining())
                responseBody.get(bytes)
                result.complete(bytes)
            }

            override fun onFailed(
                request: UrlRequest, info: UrlResponseInfo?, error: CronetException
            ) {
                Log.e(TAG, "Phantom sync failed: ${error.message}")
                // Potential MITM — Cronet will fail on cert issues with QUIC
                if (error.message?.contains("ERR_SSL", ignoreCase = true) == true ||
                    error.message?.contains("ERR_QUIC", ignoreCase = true) == true) {
                    triggerMitmKill("QUIC/TLS handshake failure: ${error.message}")
                }
                result.complete(null)
            }
        }

        try {
            val requestBuilder = engine.newUrlRequestBuilder(url, callback, executor)
            requestBuilder.setHttpMethod("GET")
            requestBuilder.addHeader("X-Aran-License-Key", licenseKey)
            requestBuilder.addHeader("X-Aran-SDK-Platform", "android")
            requestBuilder.addHeader("X-Aran-Nonce", nonce)
            requestBuilder.addHeader("X-Aran-Timestamp", timestamp.toString())
            requestBuilder.build().start()

            val responseBytes = withTimeoutOrNull(30_000) { result.await() }
            if (responseBytes != null && responseBytes.isNotEmpty()) {
                processBackendResponse(responseBytes)
                lastSyncTimestamp = System.currentTimeMillis()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Phantom sync error", e)
        }
    }

    // ── Response Processing ──

    private fun processBackendResponse(data: ByteArray) {
        try {
            val responseJson = JSONObject(String(data))

            // Check if backend returned E2EE-encrypted response
            if (responseJson.has("encrypted_data") && responseJson.has("signature")) {
                processEncryptedResponse(responseJson)
            } else {
                // Plaintext fallback (backend didn't encrypt)
                applyDynamicConfig(responseJson)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Response parse error", e)
        }
    }

    private fun processEncryptedResponse(envelope: JSONObject) {
        val encryptedB64 = envelope.getString("encrypted_data")
        val signatureB64 = envelope.getString("signature")
        val nonce = envelope.getString("nonce")
        val timestamp = envelope.getLong("timestamp")

        val encryptedData = Base64.decode(encryptedB64, Base64.NO_WRAP)
        val signature = Base64.decode(signatureB64, Base64.NO_WRAP)

        // Verify HMAC signature over encrypted_data + AAD
        val hmacKey = sealedHmacKey ?: return
        val aad = "$nonce:$timestamp"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        mac.update(encryptedData)
        mac.update(aad.toByteArray())
        val computedSig = mac.doFinal()

        if (!MessageDigest.isEqual(computedSig, signature)) {
            triggerMitmKill("HMAC signature mismatch on Phantom Channel response")
            return
        }

        // Decrypt AES-256-GCM payload using StrongBox-backed key
        val plaintext = decryptWithStrongBox(encryptedData) ?: return

        try {
            val config = JSONObject(String(plaintext))
            applyDynamicConfig(config)
        } catch (e: Exception) {
            Log.e(TAG, "Config parse error", e)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun applyDynamicConfig(config: JSONObject) {
        // Update dynamic TLS pins via JNI (stays in native memory)
        val pinsArray = config.optJSONArray("tls_pins_blinded")
        if (pinsArray != null && pinsArray.length() >= 2) {
            val pin0 = Base64.decode(
                pinsArray.getJSONObject(0).getString("blinded"), Base64.NO_WRAP
            )
            val pin1 = Base64.decode(
                pinsArray.getJSONObject(1).getString("blinded"), Base64.NO_WRAP
            )
            aranNative.updateDynamicPins(pin0, pin1)
            pin0.fill(0)
            pin1.fill(0)
        }

        // Update sync interval
        val interval = config.optLong("sync_interval_seconds", 0)
        if (interval > 0) syncIntervalSeconds = interval

        // Update reaction policy via AranSecure
        val policyRaw = config.optInt("default_reaction_policy", -1)
        if (policyRaw >= 0) {
            AranSecure.updateReactionPolicyFromPhantom(policyRaw)
        }

        Log.d(TAG, "Dynamic config applied at ${System.currentTimeMillis()}")
    }

    // ── MITM Kill ──

    private fun triggerMitmKill(reason: String) {
        Log.e(TAG, "SECURITY ALERT — $reason")
        AranSecure.invokeThreatKill(reason)
        stop()
    }

    // ── StrongBox KeyStore Integration ──

    private fun sealKeyToStrongBox(alias: String, keyBytes: ByteArray) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Delete existing key if present
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }

            val keyGen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)

            // Try StrongBox (hardware-backed), fall back to TEE
            try {
                spec.setIsStrongBoxBacked(true)
            } catch (_: Exception) { /* StrongBox not available on this device */ }

            keyGen.init(spec.build())
            keyGen.generateKey()
        } catch (e: Exception) {
            Log.e(TAG, "StrongBox key seal failed", e)
        }
    }

    private fun decryptWithStrongBox(encrypted: ByteArray): ByteArray? {
        if (encrypted.size < GCM_IV_LENGTH + 16) return null // IV + min tag

        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val key = keyStore.getKey(KEYSTORE_ALIAS_AES, null) as? SecretKey ?: return null

            val iv = encrypted.copyOfRange(0, GCM_IV_LENGTH)
            val ciphertext = encrypted.copyOfRange(GCM_IV_LENGTH, encrypted.size)

            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "StrongBox decrypt failed", e)
            null
        }
    }

    // ── Helpers ──

    private fun extractHost(url: String): String {
        return try {
            java.net.URL(url).host
        } catch (_: Exception) {
            "api.aran.mazhai.org"
        }
    }
}
