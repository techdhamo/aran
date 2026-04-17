package org.mazhai.aran.internal

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * AranTelemetryQueue
 *
 * Tamper-proof local queue for telemetry payloads.
 *
 * Security design:
 * - Payloads are already RSA-encrypted by TelemetryClient before being stored.
 *   This queue is therefore a "dumb" encrypted transport buffer — even if an
 *   attacker extracts the file, each blob can only be decrypted by the Aran
 *   backend private key.
 * - The queue itself is backed by EncryptedSharedPreferences (AES-256-GCM)
 *   which adds a second layer of local confidentiality and prevents replay
 *   of individual ciphertext blobs by deleting them after flush.
 * - Payloads include a monotonically increasing sequence number stored in
 *   the encrypted prefs so the backend can detect gaps and replay attempts.
 */
internal object AranTelemetryQueue {

    private const val TAG = "AranTelemetryQueue"
    private const val PREFS_FILE = "aran_telemetry_queue"
    private const val KEY_QUEUE = "q"
    private const val KEY_SEQ = "seq"
    private const val MAX_QUEUE_SIZE = 500

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        prefs = EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun enqueue(encryptedPayloadBase64: String) {
        synchronized(this) {
            val arr = loadQueue()
            if (arr.length() >= MAX_QUEUE_SIZE) {
                Log.w(TAG, "Queue full (${arr.length()}); dropping oldest entry")
                arr.remove(0)
            }
            val seq = prefs.getLong(KEY_SEQ, 0L) + 1
            prefs.edit().putLong(KEY_SEQ, seq).apply()

            val entry = JSONObject().apply {
                put("seq", seq)
                put("payload", encryptedPayloadBase64)
                put("queued_at", System.currentTimeMillis())
            }
            arr.put(entry)
            prefs.edit().putString(KEY_QUEUE, arr.toString()).apply()
        }
    }

    fun drainAll(): List<QueuedEntry> {
        synchronized(this) {
            val arr = loadQueue()
            if (arr.length() == 0) return emptyList()
            val entries = (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                QueuedEntry(
                    seq = obj.getLong("seq"),
                    encryptedPayloadBase64 = obj.getString("payload"),
                    queuedAt = obj.getLong("queued_at")
                )
            }
            prefs.edit().putString(KEY_QUEUE, JSONArray().toString()).apply()
            return entries
        }
    }

    fun size(): Int {
        synchronized(this) { return loadQueue().length() }
    }

    private fun loadQueue(): JSONArray {
        val raw = prefs.getString(KEY_QUEUE, null) ?: return JSONArray()
        return try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
    }

    data class QueuedEntry(
        val seq: Long,
        val encryptedPayloadBase64: String,
        val queuedAt: Long
    )
}
