package org.mazhai.aran.bridge

import android.content.Context
import android.content.Intent
import org.json.JSONObject
import org.mazhai.aran.DeviceStatus

/**
 * AranHybridBridge - Cross-Platform Threat Broadcast
 * 
 * Broadcasts threat detection events to hybrid frameworks (React Native, Flutter, Ionic)
 * via standard Android Intent mechanism.
 * 
 * This allows JavaScript/Dart developers to handle native security events
 * without writing any Kotlin code.
 * 
 * React Native Integration:
 * ```javascript
 * import { DeviceEventEmitter } from 'react-native';
 * 
 * DeviceEventEmitter.addListener('org.mazhai.aran.THREAT_DETECTED', (event) => {
 *   const payload = JSON.parse(event.payload);
 *   console.log('Threat detected:', payload);
 *   // Show custom UI
 * });
 * ```
 * 
 * Flutter Integration:
 * ```dart
 * static const EventChannel _channel = EventChannel('org.mazhai.aran/threats');
 * 
 * _channel.receiveBroadcastStream().listen((event) {
 *   final payload = jsonDecode(event['payload']);
 *   print('Threat detected: $payload');
 *   // Show custom UI
 * });
 * ```
 * 
 * Ionic/Cordova Integration:
 * ```javascript
 * window.addEventListener('org.mazhai.aran.THREAT_DETECTED', (event) => {
 *   const payload = JSON.parse(event.detail.payload);
 *   console.log('Threat detected:', payload);
 *   // Show custom UI
 * });
 * ```
 */
object AranHybridBridge {

    private const val ACTION_THREAT_DETECTED = "org.mazhai.aran.THREAT_DETECTED"
    private const val EXTRA_PAYLOAD = "payload"
    private const val EXTRA_REACTION_POLICY = "reactionPolicy"

    /**
     * Broadcast threat detection event to hybrid frameworks
     * 
     * @param context Android context
     * @param status Device security status
     * @param policy Configured reaction policy
     */
    fun broadcastThreatToHybrid(context: Context, status: DeviceStatus, policy: String) {
        try {
            val payload = serializeDeviceStatus(status)
            
            val intent = Intent(ACTION_THREAT_DETECTED).apply {
                putExtra(EXTRA_PAYLOAD, payload.toString())
                putExtra(EXTRA_REACTION_POLICY, policy)
            }
            
            context.sendBroadcast(intent)
            
            android.util.Log.i("AranHybridBridge", 
                "Broadcast sent: $ACTION_THREAT_DETECTED with policy=$policy")
        } catch (e: Exception) {
            android.util.Log.e("AranHybridBridge", 
                "Failed to broadcast threat event", e)
        }
    }

    /**
     * Serialize DeviceStatus to JSON for cross-platform consumption
     */
    private fun serializeDeviceStatus(status: DeviceStatus): JSONObject {
        return JSONObject().apply {
            // RASP Bitmask
            put("raspBitmask", status.nativeThreatMask)
            
            // Individual threat flags (native C++ bitmask)
            put("isRooted", status.isRooted)
            put("fridaDetected", status.fridaDetected)
            put("debuggerAttached", status.debuggerAttached)
            put("emulatorDetected", status.emulatorDetected)
            put("hooked", status.hooked)
            put("tampered", status.tampered)
            put("untrustedInstaller", status.untrustedInstaller)
            put("developerMode", status.developerMode)
            put("adbEnabled", status.adbEnabled)
            put("envTampering", status.envTampering)
            put("runtimeIntegrity", status.runtimeIntegrity)
            put("proxyDetected", status.proxyDetected)
            put("zygiskDetected", status.zygiskDetected)
            
            // Kotlin-level detections
            put("vpnDetected", status.vpnDetected)
            put("screenRecording", status.screenRecording)
            put("keyloggerRisk", status.keyloggerRisk)
            put("untrustedKeyboard", status.untrustedKeyboard)
            put("deviceLockMissing", status.deviceLockMissing)
            put("overlayDetected", status.overlayDetected)
            put("malwarePackages", status.malwarePackages)
            put("unsecuredWifi", status.unsecuredWifi)
            put("smsForwarderApps", status.smsForwarderApps)
            put("remoteAccessApps", status.remoteAccessApps)
            
            put("timeSpoofing", status.timeSpoofing)
            put("locationSpoofing", status.locationSpoofing)
            put("screenMirroring", status.screenMirroring)
            
            // Metadata
            put("deviceFingerprint", status.deviceFingerprint)
            put("eventId", status.eventId)
            put("timestamp", status.timestamp)
            
            // Threat summary
            put("threatCount", countThreats(status))
            put("criticalThreats", getCriticalThreats(status))
        }
    }

    private fun countThreats(status: DeviceStatus): Int {
        var count = 0
        if (status.isRooted) count++
        if (status.fridaDetected) count++
        if (status.debuggerAttached) count++
        if (status.emulatorDetected) count++
        if (status.hooked) count++
        if (status.tampered) count++
        if (status.malwarePackages.isNotEmpty()) count++
        if (status.remoteAccessApps.isNotEmpty()) count++
        if (status.zygiskDetected) count++
        if (status.timeSpoofing) count++
        if (status.locationSpoofing) count++
        if (status.screenMirroring) count++
        return count
    }

    private fun getCriticalThreats(status: DeviceStatus): List<String> {
        val threats = mutableListOf<String>()
        if (status.isRooted) threats.add("ROOT")
        if (status.fridaDetected) threats.add("FRIDA")
        if (status.hooked) threats.add("HOOKED")
        if (status.tampered) threats.add("TAMPERED")
        if (status.malwarePackages.isNotEmpty()) threats.add("MALWARE")
        if (status.zygiskDetected) threats.add("ZYGISK")
        return threats
    }
}
