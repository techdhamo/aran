package org.mazhai.aran.flutter

import android.app.Activity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus
import org.mazhai.aran.security.AranSigilEngine
import org.mazhai.aran.util.AranClipboardGuard
import org.mazhai.aran.util.AranSecureWindow

class AranSecurityPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, AranThreatListener {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private var eventSink: EventChannel.EventSink? = null
    private var activity: Activity? = null
    private var flutterPluginBinding: FlutterPlugin.FlutterPluginBinding? = null
    
    private var initialized = false
    private lateinit var sigilEngine: AranSigilEngine

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        flutterPluginBinding = binding
        methodChannel = MethodChannel(binding.binaryMessenger, "flutter_aran_security")
        methodChannel.setMethodCallHandler(this)
        
        eventChannel = EventChannel(binding.binaryMessenger, "flutter_aran_security/threats")
        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
            }

            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        flutterPluginBinding = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "start" -> start(call, result)
            "checkEnvironment" -> checkEnvironment(result)
            "handleThreats" -> handleThreats(call, result)
            "enableSecureWindow" -> enableSecureWindow(result)
            "disableSecureWindow" -> disableSecureWindow(result)
            "getSyncStatus" -> getSyncStatus(result)
            "getDeviceFingerprint" -> getDeviceFingerprint(result)
            "clearClipboard" -> clearClipboard(result)
            "generateSigil" -> generateSigil(result)
            else -> result.notImplemented()
        }
    }

    private fun start(call: MethodCall, result: Result) {
        if (initialized) {
            result.error("ALREADY_INITIALIZED", "AranSecurity already initialized", null)
            return
        }

        try {
            val licenseKey = call.argument<String>("licenseKey") ?: run {
                result.error("MISSING_PARAM", "licenseKey is required", null)
                return
            }

            val environmentStr = call.argument<String>("environment") ?: "RELEASE"
            val environment = when (environmentStr) {
                "DEV" -> AranEnvironment.DEV
                "UAT" -> AranEnvironment.UAT
                else -> AranEnvironment.RELEASE
            }

            val context = flutterPluginBinding?.applicationContext ?: run {
                result.error("NO_CONTEXT", "Application context not available", null)
                return
            }

            AranSecure.start(
                context = context,
                licenseKey = licenseKey,
                environment = environment
            )
            AranSecure.setNativeThreatListener(this)

            sigilEngine = AranSigilEngine(context, licenseKey)
            initialized = true
            result.success(null)
        } catch (e: Exception) {
            result.error("INIT_FAILED", "Initialization failed: ${e.message}", null)
        }
    }

    private fun checkEnvironment(result: Result) {
        if (!initialized) {
            result.error("NOT_INITIALIZED", "AranSecurity not initialized. Call start() first.", null)
            return
        }

        try {
            val status = AranSecure.checkEnvironment()
            result.success(DeviceStatusMapper.toMap(status))
        } catch (e: Exception) {
            result.error("SCAN_FAILED", "Security scan failed: ${e.message}", null)
        }
    }

    override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
        eventSink?.success(mapOf(
            "status" to DeviceStatusMapper.toMap(status),
            "reactionPolicy" to reactionPolicy
        ))
    }

    private fun handleThreats(call: MethodCall, result: Result) {
        val statusMap = call.argument<Map<String, Any>>("status") ?: run {
            result.error("MISSING_PARAM", "status is required", null)
            return
        }

        val reactionPolicy = call.argument<String>("reactionPolicy") ?: "DEFAULT"

        try {
            val status = DeviceStatusMapper.fromMap(statusMap)
            activity?.let { act ->
                act.runOnUiThread {
                    AranSecure.handleThreats(act, status, reactionPolicy)
                    result.success(null)
                }
            } ?: result.error("NO_ACTIVITY", "No current activity", null)
        } catch (e: Exception) {
            result.error("HANDLE_FAILED", "Threat handling failed: ${e.message}", null)
        }
    }

    private fun enableSecureWindow(result: Result) {
        activity?.let { act ->
            act.runOnUiThread {
                try {
                    AranSecureWindow.enable(act)
                    result.success(null)
                } catch (e: Exception) {
                    result.error("SECURE_WINDOW_FAILED", "Failed to enable secure window: ${e.message}", null)
                }
            }
        } ?: result.error("NO_ACTIVITY", "No current activity", null)
    }

    private fun disableSecureWindow(result: Result) {
        activity?.let { act ->
            act.runOnUiThread {
                try {
                    AranSecureWindow.disable(act)
                    result.success(null)
                } catch (e: Exception) {
                    result.error("SECURE_WINDOW_FAILED", "Failed to disable secure window: ${e.message}", null)
                }
            }
        } ?: result.error("NO_ACTIVITY", "No current activity", null)
    }

    private fun getSyncStatus(result: Result) {
        try {
            result.success(mapOf(
                "lastSyncTimestamp" to AranSecure.getLastSyncTimestamp(),
                "currentRequestId" to AranSecure.getCurrentRequestId()
            ))
        } catch (e: Exception) {
            result.error("SYNC_STATUS_FAILED", "Failed to get sync status: ${e.message}", null)
        }
    }

    private fun getDeviceFingerprint(result: Result) {
        try {
            val status = AranSecure.checkEnvironment()
            result.success(status.deviceFingerprint)
        } catch (e: Exception) {
            result.error("FINGERPRINT_FAILED", "Failed to get device fingerprint: ${e.message}", null)
        }
    }

    private fun clearClipboard(result: Result) {
        try {
            val context = flutterPluginBinding?.applicationContext ?: run {
                result.error("NO_CONTEXT", "Application context not available", null)
                return
            }
            AranClipboardGuard.clearClipboard(context)
            result.success(null)
        } catch (e: Exception) {
            result.error("CLIPBOARD_FAILED", "Failed to clear clipboard: ${e.message}", null)
        }
    }

    private fun generateSigil(result: Result) {
        try {
            val status = AranSecure.checkEnvironment()
            val sigil = sigilEngine.generateSigil(status)
            result.success(sigil)
        } catch (e: Exception) {
            result.error("SIGIL_FAILED", "Failed to generate Sigil: ${e.message}", null)
        }
    }
}
