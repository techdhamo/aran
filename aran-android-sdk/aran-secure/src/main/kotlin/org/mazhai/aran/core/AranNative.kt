package org.mazhai.aran.core

class AranNative {

    companion object {
        init {
            System.loadLibrary("aran-secure")
        }

        // Static methods for Cordova plugin interface
        @JvmStatic
        external fun runAudit(selector: Int): Int

        @JvmStatic
        external fun getStatus(statusType: Int): Int

        @JvmStatic
        external fun initialize()

        @JvmStatic
        external fun shutdown()
    }

    external fun checkIntegrityNative(expectedSignatureSha256: String): Int

    // Genesis Anchor: decode XOR-chain obfuscated fallback config from JNI core.
    // Returns JSON string with base64-encoded AES key, HMAC secret, blinded TLS pins,
    // blinding salt, reaction policy, sync endpoints. Caller MUST seal to StrongBox
    // KeyStore immediately and wipe the returned string from JVM heap.
    external fun loadGenesisState(): String

    // Zero-Knowledge TLS Pin Verification: takes SHA-256 hash of server's DER cert,
    // blinds it with cryptographic salt in native, compares against Genesis/Dynamic
    // blinded pins WITHOUT ever decrypting the expected pin into plaintext RAM.
    // Returns true if cert matches a known pin, false if MITM suspected.
    external fun verifyCertBlinded(certHash: ByteArray): Boolean

    // Update dynamic TLS pins from Phantom Channel payload.
    // Called after a successful QUIC sync with mazhai-central.
    // Pins are already in blinded form (SHA256(salt || pin_hash)).
    external fun updateDynamicPins(pin0Blinded: ByteArray, pin1Blinded: ByteArray)
}
