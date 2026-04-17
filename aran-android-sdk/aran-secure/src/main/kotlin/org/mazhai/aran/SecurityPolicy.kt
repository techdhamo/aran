package org.mazhai.aran

data class SecurityPolicy(
    val autoAlert: Boolean = false,
    val killOnRoot: Boolean = false,
    val killOnFrida: Boolean = false,
    val killOnDebugger: Boolean = false,
    val killOnEmulator: Boolean = false,
    val killOnHook: Boolean = false,
    val killOnTamper: Boolean = false,
    val killOnUntrustedInstaller: Boolean = false,
    val killOnDeveloperMode: Boolean = false,
    val killOnAdbEnabled: Boolean = false,
    val killOnVpn: Boolean = false,
    val killOnEnvTampering: Boolean = false,
    val killOnRuntimeIntegrity: Boolean = false,
    val killOnScreenRecording: Boolean = false,
    val killOnKeylogger: Boolean = false,
    val killOnUntrustedKeyboard: Boolean = false,
    val killOnOverlay: Boolean = false,
    val killOnMalware: Boolean = false,
    val killOnProxy: Boolean = false,
    val killOnUnsecuredWifi: Boolean = false,
    val killOnSmsForwarder: Boolean = false,
    val killOnRemoteAccess: Boolean = false,
    // 6.2.x-Beta
    val killOnZygisk: Boolean = false,
    val killOnDeviceLockMissing: Boolean = false,
    val killOnTimeSpoofing: Boolean = false,
    val killOnLocationSpoofing: Boolean = false,
    val killOnScreenMirroring: Boolean = false
)
