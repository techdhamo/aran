package org.mazhai.aran.capacitor

import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import org.mazhai.aran.DeviceStatus

object DeviceStatusMapper {

    fun toJSObject(status: DeviceStatus): JSObject {
        return JSObject().apply {
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
            put("malwarePackages", JSArray(status.malwarePackages))
            put("smsForwarderApps", JSArray(status.smsForwarderApps))
            put("remoteAccessApps", JSArray(status.remoteAccessApps))

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

    fun fromJSObject(obj: JSObject): DeviceStatus {
        return DeviceStatus(
            deviceFingerprint = obj.getString("deviceFingerprint", ""),
            appId = obj.getString("appId", ""),
            isRooted = obj.getBoolean("isRooted", false),
            fridaDetected = obj.getBoolean("fridaDetected", false),
            debuggerAttached = obj.getBoolean("debuggerAttached", false),
            emulatorDetected = obj.getBoolean("emulatorDetected", false),
            hooked = obj.getBoolean("hooked", false),
            tampered = obj.getBoolean("tampered", false),
            untrustedInstaller = obj.getBoolean("untrustedInstaller", false),
            developerMode = obj.getBoolean("developerMode", false),
            adbEnabled = obj.getBoolean("adbEnabled", false),
            envTampering = obj.getBoolean("envTampering", false),
            runtimeIntegrity = obj.getBoolean("runtimeIntegrity", false),
            proxyDetected = obj.getBoolean("proxyDetected", false),
            vpnDetected = obj.getBoolean("vpnDetected", false),
            screenRecording = obj.getBoolean("screenRecording", false),
            keyloggerRisk = obj.getBoolean("keyloggerRisk", false),
            untrustedKeyboard = obj.getBoolean("untrustedKeyboard", false),
            deviceLockMissing = obj.getBoolean("deviceLockMissing", false),
            overlayDetected = obj.getBoolean("overlayDetected", false),
            malwarePackages = obj.getJSONArray("malwarePackages")?.let { jsArrayToList(it) } ?: emptyList(),
            unsecuredWifi = obj.getBoolean("unsecuredWifi", false),
            smsForwarderApps = obj.getJSONArray("smsForwarderApps")?.let { jsArrayToList(it) } ?: emptyList(),
            remoteAccessApps = obj.getJSONArray("remoteAccessApps")?.let { jsArrayToList(it) } ?: emptyList(),
            zygiskDetected = obj.getBoolean("zygiskDetected", false),
            timeSpoofing = obj.getBoolean("timeSpoofing", false),
            locationSpoofing = obj.getBoolean("locationSpoofing", false),
            screenMirroring = obj.getBoolean("screenMirroring", false),
            eventId = obj.getString("eventId", ""),
            nativeThreatMask = obj.getInteger("nativeThreatMask", 0),
            timestamp = obj.getLong("timestamp")
        )
    }

    private fun jsArrayToList(array: JSArray): List<String> {
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            array.getString(i)?.let { list.add(it) }
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

fun DeviceStatus.hasThreat(): Boolean {
    return isRooted || fridaDetected || debuggerAttached || emulatorDetected ||
           hooked || tampered || untrustedInstaller || developerMode ||
           adbEnabled || vpnDetected || screenRecording || keyloggerRisk ||
           untrustedKeyboard || deviceLockMissing || overlayDetected ||
           malwarePackages.isNotEmpty() || unsecuredWifi ||
           smsForwarderApps.isNotEmpty() || remoteAccessApps.isNotEmpty() ||
           zygiskDetected || timeSpoofing || locationSpoofing || screenMirroring
}
