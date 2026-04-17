package org.mazhai.aran.capacitor

import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import org.json.JSONArray
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus
import org.mazhai.aran.security.AranSigilEngine
import org.mazhai.aran.util.AranClipboardGuard
import org.mazhai.aran.util.AranSecureWindow

@CapacitorPlugin(name = "AranSecurity")
class AranSecurityPlugin : Plugin(), AranThreatListener {

    private var initialized = false
    private lateinit var sigilEngine: AranSigilEngine
    private var threatListenerCall: PluginCall? = null

    @PluginMethod
    fun start(call: PluginCall) {
        if (initialized) {
            call.reject("AranSecurity already initialized")
            return
        }

        val licenseKey = call.getString("licenseKey") ?: run {
            call.reject("licenseKey is required")
            return
        }

        val environmentStr = call.getString("environment", "RELEASE")
        val environment = when (environmentStr) {
            "DEV" -> AranEnvironment.DEV
            "UAT" -> AranEnvironment.UAT
            else -> AranEnvironment.RELEASE
        }

        try {
            activity.runOnUiThread {
                AranSecure.start(
                    context = context,
                    licenseKey = licenseKey,
                    environment = environment
                )
                AranSecure.setNativeThreatListener(this)

                sigilEngine = AranSigilEngine(context, licenseKey)
                initialized = true
                call.resolve()
            }
        } catch (e: Exception) {
            call.reject("Initialization failed: ${e.message}", e)
        }
    }

    @PluginMethod
    fun checkEnvironment(call: PluginCall) {
        if (!initialized) {
            call.reject("AranSecurity not initialized. Call start() first.")
            return
        }

        try {
            val status = AranSecure.checkEnvironment()
            val result = DeviceStatusMapper.toJSObject(status)
            call.resolve(result)
        } catch (e: Exception) {
            call.reject("Security scan failed: ${e.message}", e)
        }
    }

    @PluginMethod(returnType = PluginMethod.RETURN_CALLBACK)
    fun setThreatListener(call: PluginCall) {
        threatListenerCall = call
        call.setKeepAlive(true)
    }

    override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
        threatListenerCall?.let { call ->
            val result = JSObject().apply {
                put("status", DeviceStatusMapper.toJSObject(status))
                put("reactionPolicy", reactionPolicy)
            }
            call.resolve(result)
        }
    }

    @PluginMethod
    fun handleThreats(call: PluginCall) {
        val statusObj = call.getObject("status") ?: run {
            call.reject("status is required")
            return
        }

        val reactionPolicy = call.getString("reactionPolicy", "DEFAULT")

        try {
            val status = DeviceStatusMapper.fromJSObject(statusObj)
            activity.runOnUiThread {
                AranSecure.handleThreats(activity, status, reactionPolicy)
                call.resolve()
            }
        } catch (e: Exception) {
            call.reject("Threat handling failed: ${e.message}", e)
        }
    }

    @PluginMethod
    fun enableSecureWindow(call: PluginCall) {
        activity.runOnUiThread {
            try {
                AranSecureWindow.enable(activity)
                call.resolve()
            } catch (e: Exception) {
                call.reject("Failed to enable secure window: ${e.message}", e)
            }
        }
    }

    @PluginMethod
    fun disableSecureWindow(call: PluginCall) {
        activity.runOnUiThread {
            try {
                AranSecureWindow.disable(activity)
                call.resolve()
            } catch (e: Exception) {
                call.reject("Failed to disable secure window: ${e.message}", e)
            }
        }
    }

    @PluginMethod
    fun getSyncStatus(call: PluginCall) {
        try {
            val result = JSObject().apply {
                put("lastSyncTimestamp", AranSecure.getLastSyncTimestamp())
                put("currentRequestId", AranSecure.getCurrentRequestId())
            }
            call.resolve(result)
        } catch (e: Exception) {
            call.reject("Failed to get sync status: ${e.message}", e)
        }
    }

    @PluginMethod
    fun getDeviceFingerprint(call: PluginCall) {
        try {
            val status = AranSecure.checkEnvironment()
            val result = JSObject().apply {
                put("fingerprint", status.deviceFingerprint)
            }
            call.resolve(result)
        } catch (e: Exception) {
            call.reject("Failed to get device fingerprint: ${e.message}", e)
        }
    }

    @PluginMethod
    fun clearClipboard(call: PluginCall) {
        try {
            AranClipboardGuard.clearClipboard(context)
            call.resolve()
        } catch (e: Exception) {
            call.reject("Failed to clear clipboard: ${e.message}", e)
        }
    }

    @PluginMethod
    fun generateSigil(call: PluginCall) {
        bridge.execute {
            try {
                val status = AranSecure.checkEnvironment()
                val sigil = sigilEngine.generateSigil(status)
                val result = JSObject().apply {
                    put("sigil", sigil)
                }
                call.resolve(result)
            } catch (e: Exception) {
                call.reject("Failed to generate Sigil: ${e.message}", e)
            }
        }
    }
}
