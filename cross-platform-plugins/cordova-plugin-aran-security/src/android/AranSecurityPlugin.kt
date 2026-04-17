package org.mazhai.aran.cordova

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import org.apache.cordova.CallbackContext
import org.apache.cordova.CordovaPlugin
import org.apache.cordova.PluginResult
import org.json.JSONArray
import org.json.JSONObject
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus
import org.mazhai.aran.security.AranSigilEngine
import org.mazhai.aran.util.AranClipboardGuard
import org.mazhai.aran.util.AranSecureWindow

/**
 * Cordova Plugin Bridge for Aran Security SDK
 * 
 * Bridges JavaScript calls to native Aran Security SDK
 */
class AranSecurityPlugin : CordovaPlugin(), AranThreatListener {

    private var threatCallback: CallbackContext? = null
    private var initialized = false
    private lateinit var sigilEngine: AranSigilEngine

    override fun execute(
        action: String,
        args: JSONArray,
        callbackContext: CallbackContext
    ): Boolean {
        return when (action) {
            "start" -> {
                start(args.getJSONObject(0), callbackContext)
                true
            }
            "checkEnvironment" -> {
                checkEnvironment(callbackContext)
                true
            }
            "setThreatListener" -> {
                setThreatListener(callbackContext)
                true
            }
            "handleThreats" -> {
                handleThreats(args.getJSONObject(0), args.getString(1), callbackContext)
                true
            }
            "enableSecureWindow" -> {
                enableSecureWindow(callbackContext)
                true
            }
            "disableSecureWindow" -> {
                disableSecureWindow(callbackContext)
                true
            }
            "getSyncStatus" -> {
                getSyncStatus(callbackContext)
                true
            }
            "getDeviceFingerprint" -> {
                getDeviceFingerprint(callbackContext)
                true
            }
            "clearClipboard" -> {
                clearClipboard(callbackContext)
                true
            }
            "generateSigil" -> {
                generateSigil(callbackContext)
                true
            }
            else -> false
        }
    }

    private fun start(config: JSONObject, callbackContext: CallbackContext) {
        if (initialized) {
            callbackContext.error("AranSecurity already initialized")
            return
        }

        try {
            val licenseKey = config.getString("licenseKey")
            val environmentStr = config.optString("environment", "RELEASE")
            
            val environment = when (environmentStr) {
                "DEV" -> AranEnvironment.DEV
                "UAT" -> AranEnvironment.UAT
                else -> AranEnvironment.RELEASE
            }

            cordova.activity.runOnUiThread {
                AranSecure.start(
                    context = cordova.context,
                    licenseKey = licenseKey,
                    environment = environment
                )
                AranSecure.setNativeThreatListener(this)
                
                // Initialize Sigil Engine
                sigilEngine = AranSigilEngine(cordova.context, licenseKey)
                
                initialized = true
                callbackContext.success()
            }
        } catch (e: Exception) {
            callbackContext.error("Initialization failed: ${e.message}")
        }
    }

    private fun checkEnvironment(callbackContext: CallbackContext) {
        if (!initialized) {
            callbackContext.error("AranSecurity not initialized")
            return
        }

        try {
            val status = AranSecure.checkEnvironment()
            val result = DeviceStatusMapper.toJSON(status)
            callbackContext.success(result)
        } catch (e: Exception) {
            callbackContext.error("Security scan failed: ${e.message}")
        }
    }

    private fun setThreatListener(callbackContext: CallbackContext) {
        threatCallback = callbackContext
        
        // Keep callback active for multiple invocations
        val pluginResult = PluginResult(PluginResult.Status.NO_RESULT)
        pluginResult.keepCallback = true
        callbackContext.sendPluginResult(pluginResult)
    }

    override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
        threatCallback?.let { callback ->
            val result = JSONObject().apply {
                put("status", DeviceStatusMapper.toJSON(status))
                put("reactionPolicy", reactionPolicy)
            }
            
            val pluginResult = PluginResult(PluginResult.Status.OK, result)
            pluginResult.keepCallback = true
            callback.sendPluginResult(pluginResult)
        }
    }

    private fun handleThreats(status: JSONObject, reactionPolicy: String, callbackContext: CallbackContext) {
        cordova.activity.runOnUiThread {
            try {
                val deviceStatus = DeviceStatusMapper.fromJSON(status)
                AranSecure.handleThreats(cordova.activity, deviceStatus, reactionPolicy)
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Threat handling failed: ${e.message}")
            }
        }
    }

    private fun enableSecureWindow(callbackContext: CallbackContext) {
        cordova.activity.runOnUiThread {
            try {
                AranSecureWindow.enable(cordova.activity)
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Failed to enable secure window: ${e.message}")
            }
        }
    }

    private fun disableSecureWindow(callbackContext: CallbackContext) {
        cordova.activity.runOnUiThread {
            try {
                AranSecureWindow.disable(cordova.activity)
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Failed to disable secure window: ${e.message}")
            }
        }
    }

    private fun getSyncStatus(callbackContext: CallbackContext) {
        try {
            val result = JSONObject().apply {
                put("lastSyncTimestamp", AranSecure.getLastSyncTimestamp())
                put("currentRequestId", AranSecure.getCurrentRequestId())
            }
            callbackContext.success(result)
        } catch (e: Exception) {
            callbackContext.error("Failed to get sync status: ${e.message}")
        }
    }

    private fun getDeviceFingerprint(callbackContext: CallbackContext) {
        try {
            val status = AranSecure.checkEnvironment()
            callbackContext.success(status.deviceFingerprint)
        } catch (e: Exception) {
            callbackContext.error("Failed to get device fingerprint: ${e.message}")
        }
    }

    private fun clearClipboard(callbackContext: CallbackContext) {
        try {
            AranClipboardGuard.clearClipboard(cordova.context)
            callbackContext.success()
        } catch (e: Exception) {
            callbackContext.error("Failed to clear clipboard: ${e.message}")
        }
    }

    private fun generateSigil(callbackContext: CallbackContext) {
        cordova.threadPool.execute {
            try {
                val status = AranSecure.checkEnvironment()
                val sigil = sigilEngine.generateSigil(status)
                callbackContext.success(sigil)
            } catch (e: Exception) {
                callbackContext.error("Failed to generate Sigil: ${e.message}")
            }
        }
    }
}
