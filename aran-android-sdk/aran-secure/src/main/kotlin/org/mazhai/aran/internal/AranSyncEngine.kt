package org.mazhai.aran.internal

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.mazhai.aran.util.AranCertPinner
import java.io.IOException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cloud-Managed RASP Sync Engine
 * Polls backend every 60 seconds for dynamic threat intelligence updates
 */
internal class AranSyncEngine(
    private val context: Context,
    private val licenseKey: String,
    private val baseUrl: String = "https://api.aran.mazhai.org"
) {
    companion object {
        private const val AES_ALGORITHM = "AES/GCM/NoPadding"
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
        // PRODUCTION: Load from Android Keystore / secure vault
        private const val MASTER_AES_KEY_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        private const val HMAC_SECRET_BASE64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .certificatePinner(
            AranCertPinner.pinner(
                "api.aran.mazhai.org" to listOf(
                    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                )
            )
        )
        .connectionSpecs(listOf(
            ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                .build()
        ))
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val secureRandom = SecureRandom()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    
    private val lastSyncTimestamp = AtomicReference<Long>(0L)
    private val lastRequestId = AtomicReference<String>("")
    
    private val encryptedPrefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        EncryptedSharedPreferences.create(
            context,
            "aran_secure_config",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Start background sync loop - triggers immediately, then every 60 seconds
     */
    fun start() {
        scope.launch {
            while (isActive) {
                try {
                    syncWithCloud()
                } catch (e: Exception) {
                    // Log error but continue polling
                    android.util.Log.e("AranSyncEngine", "Sync failed: ${e.message}", e)
                }
                delay(60_000) // 60 seconds
            }
        }
    }

    /**
     * Stop background sync loop
     */
    fun stop() {
        scope.cancel()
    }

    /**
     * Fetch dynamic config from cloud and cache securely.
     * Uses E2EE: request signed with HMAC-SHA256, response decrypted with AES-256-GCM.
     */
    private suspend fun syncWithCloud() = withContext(Dispatchers.IO) {
        val nonce = UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        val url = "$baseUrl/api/v1/config/sync?os=android&rasp_version=1.0.0"

        val hmacSignature = computeHmac("GET:$url:$nonce:$timestamp")

        val request = Request.Builder()
            .url(url)
            .get()
            .header("X-Aran-License-Key", licenseKey)
            .header("X-Aran-Nonce", nonce)
            .header("X-Aran-Timestamp", timestamp.toString())
            .header("X-Aran-Signature", hmacSignature)
            .build()

        try {
            val response = client.newCall(request).execute()

            if (response.isSuccessful) {
                val body = response.body?.string()
                if (body != null) {
                    val decrypted = decryptResponse(body, nonce, timestamp)
                    if (decrypted != null) {
                        parseAndCacheConfig(decrypted)
                        lastSyncTimestamp.set(System.currentTimeMillis())
                    }
                }
            }
            response.close()
        } catch (e: IOException) {
            // Fallback to cached config
        }
    }

    /**
     * Compute HMAC-SHA256 signature for request authentication.
     */
    private fun computeHmac(data: String): String {
        val hmacKey = SecretKeySpec(Base64.decode(HMAC_SECRET_BASE64, Base64.NO_WRAP), HMAC_ALGORITHM)
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(hmacKey)
        val sig = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(sig, Base64.NO_WRAP)
    }

    /**
     * Encrypt a JSON payload with AES-256-GCM + HMAC-SHA256 for sending to backend.
     */
    internal fun encryptPayload(plaintext: String, nonce: String, timestamp: Long): Triple<String, String, String> {
        val aesKey = SecretKeySpec(Base64.decode(MASTER_AES_KEY_BASE64, Base64.NO_WRAP), "AES")
        val iv = ByteArray(GCM_IV_LENGTH).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        val aad = "$nonce:$timestamp"
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteBuffer.allocate(iv.size + ciphertext.size).put(iv).put(ciphertext).array()
        val hmacKey = SecretKeySpec(Base64.decode(HMAC_SECRET_BASE64, Base64.NO_WRAP), HMAC_ALGORITHM)
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(hmacKey)
        mac.update(combined)
        mac.update(aad.toByteArray(Charsets.UTF_8))
        val signature = mac.doFinal()
        return Triple(
            Base64.encodeToString(combined, Base64.NO_WRAP),
            Base64.encodeToString(signature, Base64.NO_WRAP),
            aad
        )
    }

    /**
     * Verify HMAC and decrypt AES-256-GCM response from backend.
     */
    private fun decryptResponse(responseJson: String, nonce: String, timestamp: Long): String? {
        return try {
            val json = JSONObject(responseJson)
            val encryptedData = json.optString("encrypted_data", "")
            val signature = json.optString("signature", "")

            // If backend sends unencrypted (backward compat), parse directly
            if (encryptedData.isEmpty()) return responseJson

            val ivAndCiphertext = Base64.decode(encryptedData, Base64.NO_WRAP)
            val expectedSig = Base64.decode(signature, Base64.NO_WRAP)
            val aad = "$nonce:$timestamp"

            // Verify HMAC
            val hmacKey = SecretKeySpec(Base64.decode(HMAC_SECRET_BASE64, Base64.NO_WRAP), HMAC_ALGORITHM)
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(hmacKey)
            mac.update(ivAndCiphertext)
            mac.update(aad.toByteArray(Charsets.UTF_8))
            val computedSig = mac.doFinal()
            if (!MessageDigest.isEqual(expectedSig, computedSig)) return null

            // Decrypt AES-256-GCM
            val buf = ByteBuffer.wrap(ivAndCiphertext)
            val iv = ByteArray(GCM_IV_LENGTH).also { buf.get(it) }
            val ciphertext = ByteArray(buf.remaining()).also { buf.get(it) }
            val aesKey = SecretKeySpec(Base64.decode(MASTER_AES_KEY_BASE64, Base64.NO_WRAP), "AES")
            val cipher = Cipher.getInstance(AES_ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    /**
     * Parse JSON response and store in EncryptedSharedPreferences
     */
    private fun parseAndCacheConfig(jsonString: String) {
        val json = JSONObject(jsonString)
        
        val configVersion = json.optString("config_version", "v1.0.0")
        val malwarePackages = json.optJSONArray("malware_packages")?.toStringList() ?: emptyList()
        val smsForwarders = json.optJSONArray("sms_forwarders")?.toStringList() ?: emptyList()
        val remoteAccessApps = json.optJSONArray("remote_access_apps")?.toStringList() ?: emptyList()
        val sslPins = json.optJSONArray("ssl_pins")?.toStringList() ?: emptyList()
        
        val activePolicy = json.optJSONObject("active_policy")
        
        encryptedPrefs.edit().apply {
            putString("config_version", configVersion)
            putStringSet("malware_packages", malwarePackages.toSet())
            putStringSet("sms_forwarders", smsForwarders.toSet())
            putStringSet("remote_access_apps", remoteAccessApps.toSet())
            putStringSet("ssl_pins", sslPins.toSet())
            
            // Store active policy flags
            activePolicy?.let { policy ->
                putBoolean("kill_on_root", policy.optBoolean("kill_on_root", true))
                putBoolean("kill_on_frida", policy.optBoolean("kill_on_frida", true))
                putBoolean("kill_on_debugger", policy.optBoolean("kill_on_debugger", true))
                putBoolean("kill_on_emulator", policy.optBoolean("kill_on_emulator", true))
                putBoolean("kill_on_hook", policy.optBoolean("kill_on_hook", true))
                putBoolean("kill_on_tamper", policy.optBoolean("kill_on_tamper", true))
                putBoolean("kill_on_untrusted_installer", policy.optBoolean("kill_on_untrusted_installer", true))
                putBoolean("kill_on_developer_mode", policy.optBoolean("kill_on_developer_mode", true))
                putBoolean("kill_on_adb_enabled", policy.optBoolean("kill_on_adb_enabled", true))
                putBoolean("kill_on_proxy", policy.optBoolean("kill_on_proxy", false))
                putBoolean("kill_on_vpn", policy.optBoolean("kill_on_vpn", false))
                putBoolean("kill_on_malware", policy.optBoolean("kill_on_malware", false))
            }
            
            putLong("last_sync_timestamp", System.currentTimeMillis())
            apply()
        }
    }

    /**
     * Get cached malware packages (fallback to hardcoded defaults if cache empty)
     */
    fun getMalwarePackages(): List<String> {
        val cached = encryptedPrefs.getStringSet("malware_packages", null)?.toList()
        return cached ?: getDefaultMalwarePackages()
    }

    /**
     * Get cached SMS forwarder apps
     */
    fun getSmsForwarders(): List<String> {
        val cached = encryptedPrefs.getStringSet("sms_forwarders", null)?.toList()
        return cached ?: getDefaultSmsForwarders()
    }

    /**
     * Get cached remote access apps
     */
    fun getRemoteAccessApps(): List<String> {
        val cached = encryptedPrefs.getStringSet("remote_access_apps", null)?.toList()
        return cached ?: getDefaultRemoteAccessApps()
    }

    /**
     * Get cached SSL pins
     */
    fun getSslPins(): List<String> {
        val cached = encryptedPrefs.getStringSet("ssl_pins", null)?.toList()
        return cached ?: getDefaultSslPins()
    }

    /**
     * Get last sync timestamp
     */
    fun getLastSyncTimestamp(): Long {
        return lastSyncTimestamp.get()
    }

    /**
     * Get current request ID (for fraud tracking)
     */
    fun getCurrentRequestId(): String {
        return lastRequestId.get()
    }

    /**
     * Set current request ID (called by telemetry client)
     */
    fun setCurrentRequestId(requestId: String) {
        lastRequestId.set(requestId)
    }

    // ══════════════════════════════════════════════════════════════════
    // Fallback Defaults (used on first launch before cloud sync)
    // ══════════════════════════════════════════════════════════════════

    private fun getDefaultMalwarePackages(): List<String> = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "com.metasploit.stage"
    )

    private fun getDefaultSmsForwarders(): List<String> = listOf(
        "com.smsfwd",
        "com.jbak2.smsforwarder",
        "com.sms.forwarder"
    )

    private fun getDefaultRemoteAccessApps(): List<String> = listOf(
        "com.teamviewer.quicksupport.market",
        "com.anydesk.anydeskandroid",
        "com.realvnc.viewer.android"
    )

    private fun getDefaultSslPins(): List<String> = listOf(
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )

    // ══════════════════════════════════════════════════════════════════
    // Utility Extensions
    // ══════════════════════════════════════════════════════════════════

    private fun JSONArray.toStringList(): List<String> {
        val list = mutableListOf<String>()
        for (i in 0 until length()) {
            list.add(getString(i))
        }
        return list
    }
}
