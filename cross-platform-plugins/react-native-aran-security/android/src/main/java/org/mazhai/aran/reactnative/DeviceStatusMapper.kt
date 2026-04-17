package org.mazhai.aran.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import org.mazhai.aran.DeviceStatus

object DeviceStatusMapper {

    fun toWritableMap(status: DeviceStatus): WritableMap {
        return Arguments.createMap().apply {
            // Native C++ detections
            putBoolean("isRooted", status.isRooted)
            putBoolean("fridaDetected", status.fridaDetected)
            putBoolean("debuggerAttached", status.debuggerAttached)
            putBoolean("emulatorDetected", status.emulatorDetected)
            putBoolean("hooked", status.hooked)
            putBoolean("tampered", status.tampered)
            putBoolean("untrustedInstaller", status.untrustedInstaller)
            putBoolean("developerMode", status.developerMode)
            putBoolean("adbEnabled", status.adbEnabled)
            putBoolean("envTampering", status.envTampering)
            putBoolean("runtimeIntegrity", status.runtimeIntegrity)
            putBoolean("proxyDetected", status.proxyDetected)
            putBoolean("zygiskDetected", status.zygiskDetected)

            // Kotlin-level detections
            putBoolean("vpnDetected", status.vpnDetected)
            putBoolean("screenRecording", status.screenRecording)
            putBoolean("keyloggerRisk", status.keyloggerRisk)
            putBoolean("untrustedKeyboard", status.untrustedKeyboard)
            putBoolean("deviceLockMissing", status.deviceLockMissing)
            putBoolean("overlayDetected", status.overlayDetected)
            putBoolean("unsecuredWifi", status.unsecuredWifi)
            putBoolean("timeSpoofing", status.timeSpoofing)
            putBoolean("locationSpoofing", status.locationSpoofing)
            putBoolean("screenMirroring", status.screenMirroring)

            // Lists
            putArray("malwarePackages", listToWritableArray(status.malwarePackages))
            putArray("smsForwarderApps", listToWritableArray(status.smsForwarderApps))
            putArray("remoteAccessApps", listToWritableArray(status.remoteAccessApps))

            // Metadata
            putString("deviceFingerprint", status.deviceFingerprint)
            putString("appId", status.appId)
            putString("eventId", status.eventId)
            putInt("nativeThreatMask", status.nativeThreatMask)
            putDouble("timestamp", status.timestamp.toDouble())

            // Summary
            putBoolean("hasThreat", status.hasThreat())
            putInt("threatCount", countThreats(status))
        }
    }

    fun fromReadableMap(map: ReadableMap): DeviceStatus {
        return DeviceStatus(
            deviceFingerprint = map.getString("deviceFingerprint") ?: "",
            appId = map.getString("appId") ?: "",
            isRooted = map.getBoolean("isRooted"),
            fridaDetected = map.getBoolean("fridaDetected"),
            debuggerAttached = map.getBoolean("debuggerAttached"),
            emulatorDetected = map.getBoolean("emulatorDetected"),
            hooked = map.getBoolean("hooked"),
            tampered = map.getBoolean("tampered"),
            untrustedInstaller = map.getBoolean("untrustedInstaller"),
            developerMode = map.getBoolean("developerMode"),
            adbEnabled = map.getBoolean("adbEnabled"),
            envTampering = map.getBoolean("envTampering"),
            runtimeIntegrity = map.getBoolean("runtimeIntegrity"),
            proxyDetected = map.getBoolean("proxyDetected"),
            vpnDetected = map.getBoolean("vpnDetected"),
            screenRecording = map.getBoolean("screenRecording"),
            keyloggerRisk = map.getBoolean("keyloggerRisk"),
            untrustedKeyboard = map.getBoolean("untrustedKeyboard"),
            deviceLockMissing = map.getBoolean("deviceLockMissing"),
            overlayDetected = map.getBoolean("overlayDetected"),
            malwarePackages = readableArrayToList(map.getArray("malwarePackages")),
            unsecuredWifi = map.getBoolean("unsecuredWifi"),
            smsForwarderApps = readableArrayToList(map.getArray("smsForwarderApps")),
            remoteAccessApps = readableArrayToList(map.getArray("remoteAccessApps")),
            zygiskDetected = if (map.hasKey("zygiskDetected")) map.getBoolean("zygiskDetected") else false,
            timeSpoofing = if (map.hasKey("timeSpoofing")) map.getBoolean("timeSpoofing") else false,
            locationSpoofing = if (map.hasKey("locationSpoofing")) map.getBoolean("locationSpoofing") else false,
            screenMirroring = if (map.hasKey("screenMirroring")) map.getBoolean("screenMirroring") else false,
            eventId = map.getString("eventId") ?: "",
            nativeThreatMask = if (map.hasKey("nativeThreatMask")) map.getInt("nativeThreatMask") else 0,
            timestamp = if (map.hasKey("timestamp")) map.getDouble("timestamp").toLong() else System.currentTimeMillis()
        )
    }

    private fun listToWritableArray(list: List<String>): WritableArray {
        return Arguments.createArray().apply {
            list.forEach { pushString(it) }
        }
    }

    private fun readableArrayToList(array: com.facebook.react.bridge.ReadableArray?): List<String> {
        if (array == null) return emptyList()
        val list = mutableListOf<String>()
        for (i in 0 until array.size()) {
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
