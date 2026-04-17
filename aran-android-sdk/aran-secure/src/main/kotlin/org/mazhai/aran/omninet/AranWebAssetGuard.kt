package org.mazhai.aran.omninet

import android.content.Context
import android.util.Base64
import android.util.Log
import java.io.InputStream
import java.security.MessageDigest

/**
 * AranWebAssetGuard
 *
 * Verifies the SHA-256 integrity of web assets (JS/HTML) loaded into a WebView
 * against a set of expected hashes registered at SDK init time.
 *
 * An attacker who modifies local Cordova/Capacitor assets to extract data or
 * bypass bridge checks will cause a hash mismatch here, triggering a threat event.
 *
 * Usage:
 *   // At init time, register expected hashes:
 *   AranWebAssetGuard.register("www/index.html", "sha256-base64...")
 *   AranWebAssetGuard.register("www/cordova.js", "sha256-base64...")
 *
 *   // Before any WebView navigation, verify:
 *   val result = AranWebAssetGuard.verify(context)
 *   if (!result.allPassed) { // report threat }
 */
object AranWebAssetGuard {

    private const val TAG = "AranWebAssetGuard"

    data class AssetEntry(val assetPath: String, val expectedSha256Base64: String)
    data class VerificationResult(
        val allPassed: Boolean,
        val failedAssets: List<String>
    )

    private val registry = mutableListOf<AssetEntry>()

    fun register(assetPath: String, expectedSha256Base64: String) {
        registry.add(AssetEntry(assetPath, expectedSha256Base64))
    }

    fun registerAll(entries: Map<String, String>) {
        entries.forEach { (path, hash) -> register(path, hash) }
    }

    fun verify(context: Context): VerificationResult {
        if (registry.isEmpty()) {
            return VerificationResult(allPassed = true, failedAssets = emptyList())
        }
        val failed = mutableListOf<String>()
        val md = MessageDigest.getInstance("SHA-256")

        for (entry in registry) {
            try {
                val inputStream: InputStream = context.assets.open(entry.assetPath)
                val bytes = inputStream.readBytes()
                inputStream.close()

                val hash = md.digest(bytes)
                md.reset()
                val actual = Base64.encodeToString(hash, Base64.NO_WRAP)

                if (actual != entry.expectedSha256Base64) {
                    Log.e(TAG, "TAMPERED: ${entry.assetPath} expected=${entry.expectedSha256Base64} got=$actual")
                    failed.add(entry.assetPath)
                }
            } catch (e: Exception) {
                Log.e(TAG, "MISSING or UNREADABLE: ${entry.assetPath}", e)
                failed.add(entry.assetPath)
            }
        }
        return VerificationResult(allPassed = failed.isEmpty(), failedAssets = failed)
    }

    /**
     * Compute the SHA-256 hash of an asset so callers can build the registry
     * during development without manual pre-computation.
     */
    fun computeHash(context: Context, assetPath: String): String {
        val inputStream: InputStream = context.assets.open(assetPath)
        val bytes = inputStream.readBytes()
        inputStream.close()
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }
}
