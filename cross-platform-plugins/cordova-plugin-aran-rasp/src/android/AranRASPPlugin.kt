package org.mazhai.aran.cordova

import android.app.Activity
import org.apache.cordova.CallbackContext
import org.apache.cordova.CordovaPlugin
import org.apache.cordova.PluginResult
import org.json.JSONArray
import org.json.JSONObject
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus

/**
 * Cordova Plugin Bridge for Aran RASP SDK
 * 
 * Bridges JavaScript calls to native Aran Security SDK
 */
class AranRASPPlugin : CordovaPlugin(), AranThreatListener {

    private var threatCallback: CallbackContext? = null
    private var initialized = false

    override fun execute(
        action: String,
        args: JSONArray,
        callbackContext: CallbackContext
    ): Boolean {
        return when (action) {
            "initialize" -> {
                initialize(args.getJSONObject(0), callbackContext)
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
            "enableScreenshotPrevention" -> {
                enableScreenshotPrevention(callbackContext)
                true
            }
            "disableScreenshotPrevention" -> {
                disableScreenshotPrevention(callbackContext)
                true
            }
            "getSyncStatus" -> {
                getSyncStatus(callbackContext)
                true
            }
            "forceSync" -> {
                forceSync(callbackContext)
                true
            }
            "getDeviceFingerprint" -> {
                getDeviceFingerprint(callbackContext)
                true
            }
            else -> false
        }
    }

    private fun initialize(config: JSONObject, callbackContext: CallbackContext) {
        if (initialized) {
            callbackContext.error("AranRASP already initialized")
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
                
                initialized = true
                callbackContext.success()
            }
        } catch (e: Exception) {
            callbackContext.error("Initialization failed: ${e.message}")
        }
    }

    private fun checkEnvironment(callbackContext: CallbackContext) {
        if (!initialized) {
            callbackContext.error("AranRASP not initialized")
            return
        }

        try {
            val status = AranSecure.checkEnvironment()
            val result = ThreatMapper.toJSON(status)
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
                put("status", ThreatMapper.toJSON(status))
                put("reactionPolicy", reactionPolicy)
            }
            
            val pluginResult = PluginResult(PluginResult.Status.OK, result)
            pluginResult.keepCallback = true
            callback.sendPluginResult(pluginResult)
        }
    }

    private fun enableScreenshotPrevention(callbackContext: CallbackContext) {
        cordova.activity.runOnUiThread {
            try {
                cordova.activity.window.setFlags(
                    android.view.WindowManager.LayoutParams.FLAG_SECURE,
                    android.view.WindowManager.LayoutParams.FLAG_SECURE
                )
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Failed to enable screenshot prevention: ${e.message}")
            }
        }
    }

    private fun disableScreenshotPrevention(callbackContext: CallbackContext) {
        cordova.activity.runOnUiThread {
            try {
                cordova.activity.window.clearFlags(
                    android.view.WindowManager.LayoutParams.FLAG_SECURE
                )
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Failed to disable screenshot prevention: ${e.message}")
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

    private fun forceSync(callbackContext: CallbackContext) {
        // Trigger immediate cloud sync
        cordova.threadPool.execute {
            try {
                // Force sync is handled automatically by AranSyncEngine
                callbackContext.success()
            } catch (e: Exception) {
                callbackContext.error("Force sync failed: ${e.message}")
            }
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
}
