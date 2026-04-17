package org.mazhai.aran.flutter

import org.mazhai.aran.DeviceStatus

object DeviceStatusMapper {

    fun toMap(status: DeviceStatus): Map<String, Any> {
        return mapOf(
            "isRooted" to status.isRooted,
            "fridaDetected" to status.fridaDetected,
            "debuggerAttached" to status.debuggerAttached,
            "emulatorDetected" to status.emulatorDetected,
            "hooked" to status.hooked,
            "tampered" to status.tampered,
            "untrustedInstaller" to status.untrustedInstaller,
            "developerMode" to status.developerMode,
            "adbEnabled" to status.adbEnabled,
            "envTampering" to status.envTampering,
            "runtimeIntegrity" to status.runtimeIntegrity,
            "proxyDetected" to status.proxyDetected,
            "zygiskDetected" to status.zygiskDetected,
            "vpnDetected" to status.vpnDetected,
            "screenRecording" to status.screenRecording,
            "keyloggerRisk" to status.keyloggerRisk,
            "untrustedKeyboard" to status.untrustedKeyboard,
            "deviceLockMissing" to status.deviceLockMissing,
            "overlayDetected" to status.overlayDetected,
            "unsecuredWifi" to status.unsecuredWifi,
            "timeSpoofing" to status.timeSpoofing,
            "locationSpoofing" to status.locationSpoofing,
            "screenMirroring" to status.screenMirroring,
            "malwarePackages" to status.malwarePackages,
            "smsForwarderApps" to status.smsForwarderApps,
            "remoteAccessApps" to status.remoteAccessApps,
            "deviceFingerprint" to status.deviceFingerprint,
            "appId" to status.appId,
            "eventId" to status.eventId,
            "nativeThreatMask" to status.nativeThreatMask,
            "timestamp" to status.timestamp,
            "hasThreat" to status.hasThreat(),
            "threatCount" to countThreats(status)
        )
    }

    fun fromMap(map: Map<String, Any>): DeviceStatus {
        return DeviceStatus(
            deviceFingerprint = map["deviceFingerprint"] as String,
            appId = map["appId"] as String,
            isRooted = map["isRooted"] as Boolean,
            fridaDetected = map["fridaDetected"] as Boolean,
            debuggerAttached = map["debuggerAttached"] as Boolean,
            emulatorDetected = map["emulatorDetected"] as Boolean,
            hooked = map["hooked"] as Boolean,
            tampered = map["tampered"] as Boolean,
            untrustedInstaller = map["untrustedInstaller"] as Boolean,
            developerMode = map["developerMode"] as Boolean,
            adbEnabled = map["adbEnabled"] as Boolean,
            envTampering = map["envTampering"] as Boolean,
            runtimeIntegrity = map["runtimeIntegrity"] as Boolean,
            proxyDetected = map["proxyDetected"] as Boolean,
            vpnDetected = map["vpnDetected"] as Boolean,
            screenRecording = map["screenRecording"] as Boolean,
            keyloggerRisk = map["keyloggerRisk"] as Boolean,
            untrustedKeyboard = map["untrustedKeyboard"] as Boolean,
            deviceLockMissing = map["deviceLockMissing"] as Boolean,
            overlayDetected = map["overlayDetected"] as Boolean,
            malwarePackages = (map["malwarePackages"] as? List<*>)?.filterIsInstance<String>() ?: emptyList(),
            unsecuredWifi = map["unsecuredWifi"] as Boolean,
            smsForwarderApps = (map["smsForwarderApps"] as? List<*>)?.filterIsInstance<String>() ?: emptyList(),
            remoteAccessApps = (map["remoteAccessApps"] as? List<*>)?.filterIsInstance<String>() ?: emptyList(),
            zygiskDetected = (map["zygiskDetected"] as? Boolean) ?: false,
            timeSpoofing = (map["timeSpoofing"] as? Boolean) ?: false,
            locationSpoofing = (map["locationSpoofing"] as? Boolean) ?: false,
            screenMirroring = (map["screenMirroring"] as? Boolean) ?: false,
            eventId = (map["eventId"] as? String) ?: "",
            nativeThreatMask = (map["nativeThreatMask"] as? Int) ?: 0,
            timestamp = (map["timestamp"] as? Long) ?: System.currentTimeMillis()
        )
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
