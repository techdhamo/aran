package org.mazhai.aran

import java.util.UUID

data class DeviceStatus(
    val deviceFingerprint: String,
    val appId: String,
    // Native bitmask signals (C++)
    val isRooted: Boolean,
    val fridaDetected: Boolean,
    val debuggerAttached: Boolean,
    val emulatorDetected: Boolean,
    val hooked: Boolean,
    val tampered: Boolean,
    val untrustedInstaller: Boolean,
    val developerMode: Boolean,
    val adbEnabled: Boolean,
    val envTampering: Boolean,
    val runtimeIntegrity: Boolean,
    val proxyDetected: Boolean,
    val zygiskDetected: Boolean = false,
    val anonElfDetected: Boolean = false,
    val zygiskFdDetected: Boolean = false,
    // Kotlin-level signals
    val vpnDetected: Boolean,
    val screenRecording: Boolean,
    val keyloggerRisk: Boolean,
    val untrustedKeyboard: Boolean,
    val deviceLockMissing: Boolean,
    val overlayDetected: Boolean,
    val malwarePackages: List<String>,
    val unsecuredWifi: Boolean,
    val smsForwarderApps: List<String>,
    val remoteAccessApps: List<String>,
    val timeSpoofing: Boolean = false,
    val locationSpoofing: Boolean = false,
    val screenMirroring: Boolean = false,
    // Metadata
    val eventId: String = UUID.randomUUID().toString(),
    val nativeThreatMask: Int = 0,
    val timestamp: Long = System.currentTimeMillis()
)
