package org.mazhai.aran.reactnative

import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus
import org.mazhai.aran.security.AranSigilEngine
import org.mazhai.aran.util.AranClipboardGuard
import org.mazhai.aran.util.AranSecureWindow

class AranSecurityModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext), AranThreatListener {

    private var initialized = false
    private lateinit var sigilEngine: AranSigilEngine

    override fun getName(): String {
        return NAME
    }

    @ReactMethod
    fun start(options: ReadableMap, promise: Promise) {
        if (initialized) {
            promise.reject("ALREADY_INITIALIZED", "AranSecurity already initialized")
            return
        }

        try {
            val licenseKey = options.getString("licenseKey") ?: run {
                promise.reject("MISSING_PARAM", "licenseKey is required")
                return
            }

            val environmentStr = options.getString("environment") ?: "RELEASE"
            val environment = when (environmentStr) {
                "DEV" -> AranEnvironment.DEV
                "UAT" -> AranEnvironment.UAT
                else -> AranEnvironment.RELEASE
            }

            UiThreadUtil.runOnUiThread {
                AranSecure.start(
                    context = reactApplicationContext,
                    licenseKey = licenseKey,
                    environment = environment
                )
                AranSecure.setNativeThreatListener(this)

                sigilEngine = AranSigilEngine(reactApplicationContext, licenseKey)
                initialized = true
                promise.resolve(null)
            }
        } catch (e: Exception) {
            promise.reject("INIT_FAILED", "Initialization failed: ${e.message}", e)
        }
    }

    @ReactMethod
    fun checkEnvironment(promise: Promise) {
        if (!initialized) {
            promise.reject("NOT_INITIALIZED", "AranSecurity not initialized. Call start() first.")
            return
        }

        try {
            val status = AranSecure.checkEnvironment()
            val result = DeviceStatusMapper.toWritableMap(status)
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("SCAN_FAILED", "Security scan failed: ${e.message}", e)
        }
    }

    override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
        val params = Arguments.createMap().apply {
            putMap("status", DeviceStatusMapper.toWritableMap(status))
            putString("reactionPolicy", reactionPolicy)
        }

        reactApplicationContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit("AranThreatDetected", params)
    }

    @ReactMethod
    fun handleThreats(statusMap: ReadableMap, reactionPolicy: String, promise: Promise) {
        try {
            val status = DeviceStatusMapper.fromReadableMap(statusMap)
            currentActivity?.let { activity ->
                UiThreadUtil.runOnUiThread {
                    AranSecure.handleThreats(activity, status, reactionPolicy)
                    promise.resolve(null)
                }
            } ?: promise.reject("NO_ACTIVITY", "No current activity")
        } catch (e: Exception) {
            promise.reject("HANDLE_FAILED", "Threat handling failed: ${e.message}", e)
        }
    }

    @ReactMethod
    fun enableSecureWindow(promise: Promise) {
        currentActivity?.let { activity ->
            UiThreadUtil.runOnUiThread {
                try {
                    AranSecureWindow.enable(activity)
                    promise.resolve(null)
                } catch (e: Exception) {
                    promise.reject("SECURE_WINDOW_FAILED", "Failed to enable secure window: ${e.message}", e)
                }
            }
        } ?: promise.reject("NO_ACTIVITY", "No current activity")
    }

    @ReactMethod
    fun disableSecureWindow(promise: Promise) {
        currentActivity?.let { activity ->
            UiThreadUtil.runOnUiThread {
                try {
                    AranSecureWindow.disable(activity)
                    promise.resolve(null)
                } catch (e: Exception) {
                    promise.reject("SECURE_WINDOW_FAILED", "Failed to disable secure window: ${e.message}", e)
                }
            }
        } ?: promise.reject("NO_ACTIVITY", "No current activity")
    }

    @ReactMethod
    fun getSyncStatus(promise: Promise) {
        try {
            val result = Arguments.createMap().apply {
                putDouble("lastSyncTimestamp", AranSecure.getLastSyncTimestamp().toDouble())
                putString("currentRequestId", AranSecure.getCurrentRequestId())
            }
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("SYNC_STATUS_FAILED", "Failed to get sync status: ${e.message}", e)
        }
    }

    @ReactMethod
    fun getDeviceFingerprint(promise: Promise) {
        try {
            val status = AranSecure.checkEnvironment()
            promise.resolve(status.deviceFingerprint)
        } catch (e: Exception) {
            promise.reject("FINGERPRINT_FAILED", "Failed to get device fingerprint: ${e.message}", e)
        }
    }

    @ReactMethod
    fun clearClipboard(promise: Promise) {
        try {
            AranClipboardGuard.clearClipboard(reactApplicationContext)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("CLIPBOARD_FAILED", "Failed to clear clipboard: ${e.message}", e)
        }
    }

    @ReactMethod
    fun generateSigil(promise: Promise) {
        try {
            val status = AranSecure.checkEnvironment()
            val sigil = sigilEngine.generateSigil(status)
            promise.resolve(sigil)
        } catch (e: Exception) {
            promise.reject("SIGIL_FAILED", "Failed to generate Sigil: ${e.message}", e)
        }
    }

    companion object {
        const val NAME = "AranSecurity"
    }
}
