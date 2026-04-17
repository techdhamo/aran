package org.mazhai.aran.omninet

import android.content.Context
import android.util.Log
import org.mazhai.aran.security.AranSigilEngine
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection

/**
 * AranOmniNet Legacy Java HTTP Wrapper
 * 
 * Wraps java.net.HttpURLConnection to automatically inject AranSigil headers.
 * 
 * Use Case:
 * - Legacy Java libraries that use HttpURLConnection directly
 * - Third-party SDKs that don't use OkHttp
 * - Android system APIs that use URLConnection
 * 
 * Usage:
 * ```kotlin
 * // Instead of:
 * val conn = url.openConnection() as HttpURLConnection
 * 
 * // Use:
 * val conn = AranHttpURLConnection.wrap(
 *     url.openConnection(),
 *     context,
 *     getRaspBitmask,
 *     getDeviceFingerprint
 * )
 * 
 * // All subsequent calls are automatically protected
 * conn.requestMethod = "POST"
 * conn.doOutput = true
 * conn.outputStream.write(data)
 * val response = conn.inputStream.readBytes()
 * ```
 * 
 * The wrapper intercepts connect() and getOutputStream() to inject Sigil headers.
 */
class AranHttpURLConnection private constructor(
    private val delegate: HttpURLConnection,
    private val sigilEngine: AranSigilEngine,
    private val getRaspBitmask: () -> Int,
    private val getDeviceFingerprint: () -> String
) : HttpURLConnection(delegate.url) {

    companion object {
        private const val TAG = "AranHttpURLConnection"

        /**
         * Wrap an existing HttpURLConnection with AranSigil protection
         */
        fun wrap(
            connection: URLConnection,
            context: Context,
            getRaspBitmask: () -> Int,
            getDeviceFingerprint: () -> String
        ): HttpURLConnection {
            return if (connection is HttpURLConnection) {
                val sigilEngine = AranSigilEngine(context)
                AranHttpURLConnection(connection, sigilEngine, getRaspBitmask, getDeviceFingerprint)
            } else {
                throw IllegalArgumentException("Connection must be HttpURLConnection")
            }
        }

        /**
         * Convenience method for URL.openConnection()
         */
        fun open(
            url: URL,
            context: Context,
            getRaspBitmask: () -> Int,
            getDeviceFingerprint: () -> String
        ): HttpURLConnection {
            return wrap(url.openConnection(), context, getRaspBitmask, getDeviceFingerprint)
        }
    }

    private var requestBodyBuffer: ByteArray? = null
    private var sigilInjected = false

    /**
     * Inject AranSigil headers before connection
     */
    private fun injectSigil() {
        if (sigilInjected) return

        try {
            // Compute payload hash from buffered request body
            val payloadHash = if (requestBodyBuffer != null) {
                sigilEngine.computePayloadHash(String(requestBodyBuffer!!))
            } else {
                sigilEngine.computePayloadHash("")
            }

            // Generate Sigil token
            val token = sigilEngine.generateSigilToken(
                deviceFingerprint = getDeviceFingerprint(),
                raspBitmask = getRaspBitmask(),
                payloadHash = payloadHash,
                trafficSource = "JAVA_HTTP"
            )

            val publicKey = sigilEngine.getPublicKeyBase64()

            // Inject headers into delegate connection
            delegate.setRequestProperty("X-Aran-Sigil", token)
            delegate.setRequestProperty("X-Aran-Public-Key", publicKey)

            sigilInjected = true
            Log.d(TAG, "AranSigil injected into HttpURLConnection: ${delegate.url}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to inject AranSigil", e)
            throw e
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Intercept Methods to Inject Sigil
    // ══════════════════════════════════════════════════════════════════

    override fun connect() {
        injectSigil()
        delegate.connect()
    }

    override fun getOutputStream(): OutputStream {
        // Wrap output stream to buffer request body for hash computation
        return BufferedOutputStream(delegate.outputStream) { bufferedData ->
            requestBodyBuffer = bufferedData
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Delegate All Other Methods to Original Connection
    // ══════════════════════════════════════════════════════════════════

    override fun disconnect() = delegate.disconnect()
    override fun usingProxy(): Boolean = delegate.usingProxy()
    override fun getInputStream(): InputStream = delegate.inputStream
    override fun getErrorStream(): InputStream? = delegate.errorStream
    override fun getResponseCode(): Int = delegate.responseCode
    override fun getResponseMessage(): String = delegate.responseMessage
    override fun getHeaderField(n: Int): String? = delegate.getHeaderField(n)
    override fun getHeaderFieldKey(n: Int): String? = delegate.getHeaderFieldKey(n)
    override fun getHeaderField(name: String?): String? = delegate.getHeaderField(name)
    override fun getHeaderFieldLong(name: String?, Default: Long): Long = delegate.getHeaderFieldLong(name, Default)
    override fun getHeaderFieldDate(name: String?, Default: Long): Long = delegate.getHeaderFieldDate(name, Default)

    override fun setRequestMethod(method: String?) {
        delegate.requestMethod = method
    }

    override fun getRequestMethod(): String = delegate.requestMethod

    override fun setInstanceFollowRedirects(followRedirects: Boolean) {
        delegate.instanceFollowRedirects = followRedirects
    }

    override fun getInstanceFollowRedirects(): Boolean = delegate.instanceFollowRedirects

    override fun setRequestProperty(key: String?, value: String?) {
        delegate.setRequestProperty(key, value)
    }

    override fun addRequestProperty(key: String?, value: String?) {
        delegate.addRequestProperty(key, value)
    }

    override fun getRequestProperty(key: String?): String? = delegate.getRequestProperty(key)

    override fun getRequestProperties(): MutableMap<String, MutableList<String>> = delegate.requestProperties

    /**
     * Custom OutputStream that buffers data for payload hash computation
     */
    private class BufferedOutputStream(
        private val delegate: OutputStream,
        private val onClose: (ByteArray) -> Unit
    ) : OutputStream() {

        private val buffer = mutableListOf<Byte>()

        override fun write(b: Int) {
            buffer.add(b.toByte())
            delegate.write(b)
        }

        override fun write(b: ByteArray) {
            buffer.addAll(b.toList())
            delegate.write(b)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            buffer.addAll(b.slice(off until off + len))
            delegate.write(b, off, len)
        }

        override fun flush() {
            delegate.flush()
        }

        override fun close() {
            onClose(buffer.toByteArray())
            delegate.close()
        }
    }
}

/**
 * Extension function for easy URL wrapping
 */
fun URL.openAranConnection(
    context: Context,
    getRaspBitmask: () -> Int,
    getDeviceFingerprint: () -> String
): HttpURLConnection {
    return AranHttpURLConnection.open(this, context, getRaspBitmask, getDeviceFingerprint)
}
