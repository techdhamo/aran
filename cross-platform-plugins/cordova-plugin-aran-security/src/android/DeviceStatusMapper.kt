package org.mazhai.aran.cordova

import org.json.JSONArray
import org.json.JSONObject
import org.mazhai.aran.DeviceStatus

/**
 * Maps DeviceStatus between native Kotlin and JSON for JavaScript bridge
 */
object DeviceStatusMapper {
    
    fun toJSON(status: DeviceStatus): JSONObject {
        return JSONObject().apply {
            // Native C++ detections
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
            put("unsecuredWifi", status.unsecuredWifi)
            put("timeSpoofing", status.timeSpoofing)
            put("locationSpoofing", status.locationSpoofing)
            put("screenMirroring", status.screenMirroring)
            
            // Lists
            put("malwarePackages", JSONArray(status.malwarePackages))
            put("smsForwarderApps", JSONArray(status.smsForwarderApps))
            put("remoteAccessApps", JSONArray(status.remoteAccessApps))
            
            // Metadata
            put("deviceFingerprint", status.deviceFingerprint)
            put("appId", status.appId)
            put("eventId", status.eventId)
            put("nativeThreatMask", status.nativeThreatMask)
            put("timestamp", status.timestamp)
            
            // Summary
            put("hasThreat", status.hasThreat())
            put("threatCount", countThreats(status))
        }
    }
    
    fun fromJSON(json: JSONObject): DeviceStatus {
        return DeviceStatus(
            deviceFingerprint = json.getString("deviceFingerprint"),
            appId = json.getString("appId"),
            isRooted = json.getBoolean("isRooted"),
            fridaDetected = json.getBoolean("fridaDetected"),
            debuggerAttached = json.getBoolean("debuggerAttached"),
            emulatorDetected = json.getBoolean("emulatorDetected"),
            hooked = json.getBoolean("hooked"),
            tampered = json.getBoolean("tampered"),
            untrustedInstaller = json.getBoolean("untrustedInstaller"),
            developerMode = json.getBoolean("developerMode"),
            adbEnabled = json.getBoolean("adbEnabled"),
            envTampering = json.getBoolean("envTampering"),
            runtimeIntegrity = json.getBoolean("runtimeIntegrity"),
            proxyDetected = json.getBoolean("proxyDetected"),
            vpnDetected = json.getBoolean("vpnDetected"),
            screenRecording = json.getBoolean("screenRecording"),
            keyloggerRisk = json.getBoolean("keyloggerRisk"),
            untrustedKeyboard = json.getBoolean("untrustedKeyboard"),
            deviceLockMissing = json.getBoolean("deviceLockMissing"),
            overlayDetected = json.getBoolean("overlayDetected"),
            malwarePackages = jsonArrayToList(json.getJSONArray("malwarePackages")),
            unsecuredWifi = json.getBoolean("unsecuredWifi"),
            smsForwarderApps = jsonArrayToList(json.getJSONArray("smsForwarderApps")),
            remoteAccessApps = jsonArrayToList(json.getJSONArray("remoteAccessApps")),
            zygiskDetected = json.optBoolean("zygiskDetected", false),
            timeSpoofing = json.optBoolean("timeSpoofing", false),
            locationSpoofing = json.optBoolean("locationSpoofing", false),
            screenMirroring = json.optBoolean("screenMirroring", false),
            eventId = json.optString("eventId", ""),
            nativeThreatMask = json.optInt("nativeThreatMask", 0),
            timestamp = json.optLong("timestamp", System.currentTimeMillis())
        )
    }
    
    private fun jsonArrayToList(array: JSONArray): List<String> {
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            list.add(array.getString(i))
        }
        return list
    }
    
    private fun countThreats(status: DeviceStatus): Int {
        var count = 0
        if (status.isRooted) count++
        if (status.fridaDetected) count++
        if (status.debuggerAttached) count++
        if (status.emulatorDetected) count++
        if (status.hooked) count++
        if (status.tampered) count++
        if (status.untrustedInstaller) count++
        if (status.developerMode) count++
        if (status.adbEnabled) count++
        if (status.vpnDetected) count++
        if (status.screenRecording) count++
        if (status.keyloggerRisk) count++
        if (status.untrustedKeyboard) count++
        if (status.deviceLockMissing) count++
        if (status.overlayDetected) count++
        if (status.malwarePackages.isNotEmpty()) count++
        if (status.unsecuredWifi) count++
        if (status.smsForwarderApps.isNotEmpty()) count++
        if (status.remoteAccessApps.isNotEmpty()) count++
        if (status.zygiskDetected) count++
        if (status.timeSpoofing) count++
        if (status.locationSpoofing) count++
        if (status.screenMirroring) count++
        return count
    }
}

// Extension function for DeviceStatus
fun DeviceStatus.hasThreat(): Boolean {
    return isRooted || fridaDetected || debuggerAttached || emulatorDetected ||
           hooked || tampered || untrustedInstaller || developerMode ||
           adbEnabled || vpnDetected || screenRecording || keyloggerRisk ||
           untrustedKeyboard || deviceLockMissing || overlayDetected ||
           malwarePackages.isNotEmpty() || unsecuredWifi ||
           smsForwarderApps.isNotEmpty() || remoteAccessApps.isNotEmpty() ||
           zygiskDetected || timeSpoofing || locationSpoofing || screenMirroring
}
