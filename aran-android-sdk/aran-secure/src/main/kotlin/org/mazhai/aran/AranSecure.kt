package org.mazhai.aran

import android.app.Activity
import android.app.AlertDialog
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.view.Display
import android.view.accessibility.AccessibilityManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.mazhai.aran.core.AranNative
import org.mazhai.aran.internal.AranPhantomSync
import org.mazhai.aran.internal.AranSyncEngine
import org.mazhai.aran.internal.TelemetryClient
import org.json.JSONObject
import java.util.UUID
import org.mazhai.aran.security.AranScorchedEarth

object AranSecure {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    private var initialized = false

    @Volatile
    private lateinit var applicationContext: Context

    @Volatile
    private lateinit var appId: String

    @Volatile
    private lateinit var licenseKey: String

    @Volatile
    private var expectedSignatureSha256: String = ""

    @Volatile
    private var policy: SecurityPolicy = SecurityPolicy()

    @Volatile
    private var environment: AranEnvironment = AranEnvironment.DEV

    private lateinit var telemetryClient: TelemetryClient
    private val aranNative = AranNative()
    
    @Volatile
    private var syncEngine: AranSyncEngine? = null

    @Volatile
    private var phantomSync: AranPhantomSync? = null
    
    @Volatile
    private var threatListener: AranThreatListener? = null

    // ── Public API: ONLY accepts licenseKey and environment ──
    // ALL security configurations (TLS pins, reaction policies, threat callbacks)
    // are loaded natively from the Genesis Anchor (JNI C++ core) or fetched
    // dynamically via the Phantom Channel (Cronet QUIC/UDP).
    // This prevents runtime parameter tampering by Frida hooking start().
    fun start(
        context: Context,
        licenseKey: String,
        environment: AranEnvironment
    ) {
        this.applicationContext = context.applicationContext
        this.appId = context.packageName
        this.licenseKey = licenseKey
        this.environment = environment

        if (!::telemetryClient.isInitialized) {
            telemetryClient = TelemetryClient(context.applicationContext)
        }

        if (initialized) return
        initialized = true

        // ── Step 1: Load Genesis Anchor from JNI C++ core ──
        // XOR-chain decoded in native memory → returns JSON with base64 fields
        val genesisJson: JSONObject
        try {
            val genesisRaw = aranNative.loadGenesisState()
            genesisJson = JSONObject(genesisRaw)
            // Wipe the raw string reference (JVM may GC; best-effort)
            @Suppress("UNUSED_VALUE")
            var wipe = genesisRaw
            wipe = "\u0000".repeat(genesisRaw.length)
        } catch (e: Exception) {
            Log.e(TAG, "Genesis Anchor load failed", e)
            return
        }

        // ── Step 2: Apply default reaction policy from Genesis ──
        val policyCode = genesisJson.optInt("default_reaction_policy", 3)
        policy = mapReactionPolicy(environment, policyCode)

        // ── Step 3: Initialize Cloud-Managed RASP Sync Engine (OkHttp fallback) ──
        syncEngine = AranSyncEngine(applicationContext, licenseKey)
        syncEngine?.start()

        // ── Step 4: Start Phantom Channel (Cronet QUIC/UDP to mazhai-central) ──
        // Non-blocking: connects in background over UDP, fetches dynamic config,
        // updates TLS pins + reaction policies from backend.
        // If MITM detected during sync → immediate KILL_APP.
        phantomSync = AranPhantomSync(applicationContext, licenseKey)
        phantomSync?.start(genesisJson)

        // ── Step 5: Start periodic environment scanning ──
        scope.launch {
            while (true) {
                val status = checkEnvironment()
                if (status.hasThreat()) {
                    val requestId = UUID.randomUUID().toString()
                    syncEngine?.setCurrentRequestId(requestId)
                    telemetryClient.postThreatDetected(status, requestId)
                }
                delay(30_000)
            }
        }
    }

    // Map Genesis reaction policy code + environment to SecurityPolicy
    private fun mapReactionPolicy(env: AranEnvironment, policyCode: Int): SecurityPolicy {
        return when (env) {
            AranEnvironment.DEV -> SecurityPolicy(autoAlert = true)
            AranEnvironment.UAT -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = true, killOnFrida = true, killOnDebugger = true,
                killOnEmulator = true, killOnHook = true, killOnTamper = true,
                killOnUntrustedInstaller = true, killOnEnvTampering = true,
                killOnRuntimeIntegrity = true, killOnMalware = true,
                killOnOverlay = true, killOnScreenRecording = true
            )
            AranEnvironment.RELEASE -> SecurityPolicy(
                autoAlert = policyCode >= 3, // KILL_APP = 3
                killOnRoot = true, killOnFrida = true, killOnDebugger = true,
                killOnEmulator = true, killOnHook = true, killOnTamper = true,
                killOnUntrustedInstaller = true, killOnEnvTampering = true,
                killOnRuntimeIntegrity = true, killOnMalware = true,
                killOnOverlay = true, killOnScreenRecording = true,
                killOnProxy = true, killOnZygisk = true,
                killOnTimeSpoofing = true, killOnLocationSpoofing = true,
                killOnScreenMirroring = true
            )
        }
    }

    // ── Internal: Called by AranPhantomSync to update policy dynamically ──
    internal fun updateReactionPolicyFromPhantom(policyCode: Int) {
        policy = mapReactionPolicy(environment, policyCode)
    }

    // ── Internal: Called by AranPhantomSync on MITM detection ──
    internal fun invokeThreatKill(reason: String) {
        Log.e(TAG, "MITM KILL: $reason")
        val status = if (initialized) checkEnvironment() else return
        threatListener?.onThreatDetected(status, "KILL_APP")
        // Scorched Earth: Wipe secrets, blackhole network, freeze UI
        AranScorchedEarth.execute(applicationContext, "MITM detected: $reason")
    }

    // ── Internal: Allow native listener registration (for hybrid bridges) ──
    internal fun setNativeThreatListener(listener: AranThreatListener?) {
        this.threatListener = listener
    }

    /**
     * Get last cloud sync timestamp (for UI display)
     */
    fun getLastSyncTimestamp(): Long {
        return syncEngine?.getLastSyncTimestamp() ?: 0L
    }

    /**
     * Get current request ID (for fraud tracking)
     */
    fun getCurrentRequestId(): String {
        return syncEngine?.getCurrentRequestId() ?: ""
    }

    fun checkEnvironment(): DeviceStatus {
        check(initialized) { "AranSecure.init(context, appId) must be called before checkEnvironment()." }

        val ctx = applicationContext
        val deviceFingerprint = generateDeviceFingerprint(ctx)
        val mask = aranNative.checkIntegrityNative(expectedSignatureSha256)

        // 13-bit native bitmask (6.2.x-Beta: added bit 12 for Zygisk)
        val isRooted           = (mask and 0x001) != 0
        val fridaDetected      = (mask and 0x002) != 0
        val debuggerAttached   = (mask and 0x004) != 0
        val emulatorDetected   = (mask and 0x008) != 0
        val hooked             = (mask and 0x010) != 0
        val tampered           = (mask and 0x020) != 0
        val untrustedInstaller = (mask and 0x040) != 0
        val developerMode      = (mask and 0x080) != 0
        val adbEnabled         = (mask and 0x100) != 0
        val envTampering       = (mask and 0x200) != 0
        val runtimeIntegrity   = (mask and 0x400) != 0
        val proxyDetected      = (mask and 0x800) != 0
        val zygiskDetected     = (mask and 0x1000) != 0
        val anonElfDetected    = (mask and 0x2000) != 0
        val zygiskFdDetected   = (mask and 0x4000) != 0

        // Kotlin-level detections
        val vpnDetected        = isVpnActive(ctx)
        val screenRecording    = isScreenRecordingActive(ctx)
        val keyloggerRisk      = hasKeyloggerRisk(ctx)
        val untrustedKeyboard  = hasUntrustedKeyboard(ctx)
        val deviceLockMissing  = !isDeviceSecure(ctx)
        val overlayDetected    = hasOverlayPackages(ctx)
        val malwarePackages    = findMalwarePackages(ctx)
        val unsecuredWifi      = isUnsecuredWifi(ctx)
        val smsForwarderApps   = findSmsForwarderApps(ctx)
        val remoteAccessApps   = findRemoteAccessApps(ctx)

        val timeSpoofing       = isTimeSpoofed(ctx)
        val locationSpoofing   = isLocationSpoofed(ctx)
        val screenMirroring    = isScreenMirroring(ctx)

        val status = DeviceStatus(
            deviceFingerprint = deviceFingerprint,
            appId = appId,
            isRooted = isRooted,
            fridaDetected = fridaDetected,
            debuggerAttached = debuggerAttached,
            emulatorDetected = emulatorDetected,
            hooked = hooked,
            tampered = tampered,
            untrustedInstaller = untrustedInstaller,
            developerMode = developerMode,
            adbEnabled = adbEnabled,
            envTampering = envTampering,
            runtimeIntegrity = runtimeIntegrity,
            proxyDetected = proxyDetected,
            zygiskDetected = zygiskDetected,
            anonElfDetected = anonElfDetected,
            zygiskFdDetected = zygiskFdDetected,
            vpnDetected = vpnDetected,
            screenRecording = screenRecording,
            keyloggerRisk = keyloggerRisk,
            untrustedKeyboard = untrustedKeyboard,
            deviceLockMissing = deviceLockMissing,
            overlayDetected = overlayDetected,
            malwarePackages = malwarePackages,
            unsecuredWifi = unsecuredWifi,
            smsForwarderApps = smsForwarderApps,
            remoteAccessApps = remoteAccessApps,
            timeSpoofing = timeSpoofing,
            locationSpoofing = locationSpoofing,
            screenMirroring = screenMirroring,
            nativeThreatMask = mask
        )

        val hasThreat = status.hasThreat()
        val broadcastIntent = Intent(ACTION_ALL_CHECKS_FINISHED)
        broadcastIntent.putExtra("eventId", status.eventId)
        broadcastIntent.putExtra("hasThreat", hasThreat)
        broadcastIntent.putExtra("nativeThreatMask", mask)
        broadcastIntent.setPackage(ctx.packageName)
        ctx.sendBroadcast(broadcastIntent)

        return status
    }

    /**
     * Data class for environment info used by Sigil interceptors
     */
    data class EnvironmentInfo(val bitmask: Int, val environment: AranEnvironment)

    val context: Context get() = applicationContext

    fun getDeviceFingerprint(): String {
        check(initialized) { "AranSecure must be initialized first" }
        return generateDeviceFingerprint(applicationContext)
    }

    fun getEnvironment(): EnvironmentInfo {
        check(initialized) { "AranSecure must be initialized first" }
        val mask = aranNative.checkIntegrityNative(expectedSignatureSha256)
        return EnvironmentInfo(bitmask = mask, environment = AranEnvironment.RELEASE)
    }

    private const val TAG = "AranSecure"
    const val ACTION_ALL_CHECKS_FINISHED = "org.mazhai.aran.ALL_CHECKS_FINISHED"

    fun handleThreats(activity: Activity, status: DeviceStatus, reactionPolicy: String = "DEFAULT") {
        if (!status.hasThreat()) return
        
        // CUSTOM policy: Delegate to host app via listener + hybrid broadcast
        if (reactionPolicy == "CUSTOM") {
            threatListener?.onThreatDetected(status, reactionPolicy)
            org.mazhai.aran.bridge.AranHybridBridge.broadcastThreatToHybrid(
                activity.applicationContext,
                status,
                reactionPolicy
            )
            return  // Do NOT show default dialog or kill app
        }
        
        if (!policy.autoAlert) return

        val shouldKill =
            (policy.killOnRoot && status.isRooted) ||
                (policy.killOnFrida && status.fridaDetected) ||
                (policy.killOnDebugger && status.debuggerAttached) ||
                (policy.killOnEmulator && status.emulatorDetected) ||
                (policy.killOnHook && status.hooked) ||
                (policy.killOnTamper && status.tampered) ||
                (policy.killOnUntrustedInstaller && status.untrustedInstaller) ||
                (policy.killOnDeveloperMode && status.developerMode) ||
                (policy.killOnAdbEnabled && status.adbEnabled) ||
                (policy.killOnVpn && status.vpnDetected) ||
                (policy.killOnEnvTampering && status.envTampering) ||
                (policy.killOnRuntimeIntegrity && status.runtimeIntegrity) ||
                (policy.killOnScreenRecording && status.screenRecording) ||
                (policy.killOnKeylogger && status.keyloggerRisk) ||
                (policy.killOnUntrustedKeyboard && status.untrustedKeyboard) ||
                (policy.killOnOverlay && status.overlayDetected) ||
                (policy.killOnMalware && status.malwarePackages.isNotEmpty()) ||
                (policy.killOnProxy && status.proxyDetected) ||
                (policy.killOnUnsecuredWifi && status.unsecuredWifi) ||
                (policy.killOnSmsForwarder && status.smsForwarderApps.isNotEmpty()) ||
                (policy.killOnRemoteAccess && status.remoteAccessApps.isNotEmpty()) ||
                (policy.killOnZygisk && status.zygiskDetected) ||
                (policy.killOnDeviceLockMissing && status.deviceLockMissing) ||
                (policy.killOnTimeSpoofing && status.timeSpoofing) ||
                (policy.killOnLocationSpoofing && status.locationSpoofing) ||
                (policy.killOnScreenMirroring && status.screenMirroring)

        val message = buildString {
            append("Security threat detected.\n\n")
            if (status.isRooted) append("rooted: true\n")
            if (status.fridaDetected) append("frida_detected: true\n")
            if (status.debuggerAttached) append("debugger_attached: true\n")
            if (status.emulatorDetected) append("emulator_detected: true\n")
            if (status.hooked) append("hook_detected: true\n")
            if (status.tampered) append("tamper_detected: true\n")
            if (status.untrustedInstaller) append("untrusted_installer: true\n")
            if (status.developerMode) append("developer_mode: true\n")
            if (status.adbEnabled) append("adb_enabled: true\n")
            if (status.vpnDetected) append("vpn_detected: true\n")
            if (status.envTampering) append("env_tampering: true\n")
            if (status.runtimeIntegrity) append("runtime_integrity: true\n")
            if (status.screenRecording) append("screen_recording: true\n")
            if (status.keyloggerRisk) append("keylogger_risk: true\n")
            if (status.untrustedKeyboard) append("untrusted_keyboard: true\n")
            if (status.deviceLockMissing) append("device_lock_missing: true\n")
            if (status.overlayDetected) append("overlay_detected: true\n")
            if (status.malwarePackages.isNotEmpty()) {
                append("malware_detected: ${status.malwarePackages.size} harmful app(s)\n")
                status.malwarePackages.forEach { append("  → $it\n") }
            }
            if (status.proxyDetected) append("proxy_detected: true\n")
            if (status.unsecuredWifi) append("unsecured_wifi: true\n")
            if (status.zygiskDetected) append("zygisk_detected: true\n")
            if (status.timeSpoofing) append("time_spoofing: true\n")
            if (status.locationSpoofing) append("location_spoofing: true\n")
            if (status.screenMirroring) append("screen_mirroring: true\n")
            if (status.smsForwarderApps.isNotEmpty()) {
                append("sms_forwarder_apps: ${status.smsForwarderApps.size} app(s)\n")
                status.smsForwarderApps.forEach { append("  → $it\n") }
            }
            if (status.remoteAccessApps.isNotEmpty()) {
                append("remote_access_apps: ${status.remoteAccessApps.size} app(s)\n")
                status.remoteAccessApps.forEach { append("  → $it\n") }
            }
            append("\neventId: ${status.eventId}\n")
            append("nativeMask: 0x${status.nativeThreatMask.toString(16)}\n")
        }

        activity.runOnUiThread {
            AlertDialog.Builder(activity)
                .setTitle("Aran Security Alert")
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("OK") { _, _ ->
                    if (shouldKill) {
                        // Scorched Earth: Wipe secrets, blackhole network, freeze UI
                        AranScorchedEarth.execute(activity.applicationContext, "Threat detected: KILL_APP policy")
                    }
                }
                .show()
        }
    }

    private fun generateDeviceFingerprint(context: Context): String {
        // Phase 1 placeholder: stable-per-install fingerprint should use AndroidX Security.
        // For now, we return a random UUID per process.
        return UUID.randomUUID().toString()
    }

    // ── #28 VPN Detection ──
    @Suppress("MissingPermission")
    private fun isVpnActive(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false
            val net = cm.activeNetwork ?: return false
            cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        } catch (_: Exception) { false }
    }

    // ── #23 Screen Recording Detection ──
    private fun isScreenRecordingActive(context: Context): Boolean {
        return try {
            val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? android.hardware.display.DisplayManager
                ?: return false
            dm.displays.any { it.displayId != android.view.Display.DEFAULT_DISPLAY && it.flags and android.view.Display.FLAG_PRIVATE == 0 }
        } catch (_: Exception) { false }
    }

    // ── #24 Keylogger Risk (suspicious accessibility services) ──
    private fun hasKeyloggerRisk(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
                ?: return false
            val enabled = am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            enabled.any { svc ->
                val id = svc.resolveInfo?.serviceInfo?.packageName ?: return@any false
                (svc.resolveInfo?.serviceInfo?.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0)
            }
        } catch (_: Exception) { false }
    }

    // ── #25 Untrusted Keyboard Detection ──
    private fun hasUntrustedKeyboard(context: Context): Boolean {
        return try {
            val currentIme = Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
                ?: return false
            val pkg = currentIme.substringBefore('/')
            val appInfo = context.packageManager.getApplicationInfo(pkg, 0)
            (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
        } catch (_: Exception) { false }
    }

    // ── #26 Device Lock Status ──
    private fun isDeviceSecure(context: Context): Boolean {
        return try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
                ?: return false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) km.isDeviceSecure else km.isKeyguardSecure
        } catch (_: Exception) { false }
    }

    // ── #27 Overlay Attack Detection ──
    private fun hasOverlayPackages(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
            val pm = context.packageManager
            val installed = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            installed.any { app ->
                (app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 &&
                    Settings.canDrawOverlays(context.createPackageContext(app.packageName, 0))
            }
        } catch (_: Exception) { false }
    }

    // ── #29 Malware Presence (Cloud-Managed Dynamic Blacklist) ──
    private fun findMalwarePackages(context: Context): List<String> {
        val dynamicBlacklist = syncEngine?.getMalwarePackages() ?: emptyList()
        val pm = context.packageManager
        return dynamicBlacklist.filter { pkg ->
            try { pm.getPackageInfo(pkg, 0); true } catch (_: Exception) { false }
        }
    }

    // ── #13 Unsecured Wi-Fi Detection ──
    @Suppress("DEPRECATION", "MissingPermission")
    private fun isUnsecuredWifi(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false
            val net = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(net) ?: return false
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return false
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: return false
            val info = wm.connectionInfo ?: return false
            val ssid = info.ssid?.replace("\"", "") ?: ""
            val openPatterns = listOf("free", "guest", "public", "open", "airport", "hotel")
            openPatterns.any { ssid.contains(it, ignoreCase = true) }
        } catch (_: Exception) { false }
    }

    // ── VAPT #3 SMS Forwarding App Detection (Cloud-Managed) ──
    private fun findSmsForwarderApps(context: Context): List<String> {
        val dynamicList = syncEngine?.getSmsForwarders() ?: emptyList()
        val pm = context.packageManager
        return dynamicList.filter { pkg ->
            try { pm.getPackageInfo(pkg, 0); true } catch (_: Exception) { false }
        }
    }

    // ── VAPT #4 Remote Access App Detection (Cloud-Managed) ──
    private fun findRemoteAccessApps(context: Context): List<String> {
        val dynamicList = syncEngine?.getRemoteAccessApps() ?: emptyList()
        val pm = context.packageManager
        return dynamicList.filter { pkg ->
            try { pm.getPackageInfo(pkg, 0); true } catch (_: Exception) { false }
        }
    }

    // ── Time Spoofing Detection ──
    private fun isTimeSpoofed(context: Context): Boolean {
        return try {
            // 1. Check if auto-time is disabled
            val autoTime = Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME, 1)
            if (autoTime == 0) return true

            // 2. Compare elapsed realtime (monotonic) boot-derived time with system time
            val uptimeMs = SystemClock.elapsedRealtime()
            val bootTimeMs = System.currentTimeMillis() - uptimeMs
            val prefs = context.getSharedPreferences("aran_prefs", Context.MODE_PRIVATE)
            val storedBootTime = prefs.getLong("aran_boot_time", 0L)
            if (storedBootTime > 0L) {
                val drift = kotlin.math.abs(bootTimeMs - storedBootTime)
                if (drift > 300_000) { // >5 minutes drift
                    prefs.edit().putLong("aran_boot_time", bootTimeMs).apply()
                    return true
                }
            }
            prefs.edit().putLong("aran_boot_time", bootTimeMs).apply()
            false
        } catch (_: Exception) { false }
    }

    // ── Location Spoofing Detection ──
    @Suppress("DEPRECATION")
    private fun isLocationSpoofed(context: Context): Boolean {
        return try {
            // 1. Check mock location setting (pre-M)
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                val mockEnabled = Settings.Secure.getInt(
                    context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0
                )
                if (mockEnabled == 1) return true
            }

            // 2. Check if any test provider is enabled (API 18+)
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
                ?: return false
            val providers = lm.allProviders
            for (provider in providers) {
                try {
                    val loc = lm.getLastKnownLocation(provider)
                    if (loc != null && loc.isFromMockProvider) return true
                } catch (_: SecurityException) { /* no permission */ }
            }

            // 3. Check for well-known mock location apps
            val mockApps = listOf(
                "com.lexa.fakegps", "com.incorporateapps.fakegps",
                "com.fakegps.mock", "com.blogspot.newapphorizons.fakegps",
                "ru.gavrikov.mocklocations", "com.theappninjas.gpsjoystick",
                "com.divi.fakeGPS", "com.lkr.fakelocation"
            )
            val pm = context.packageManager
            for (app in mockApps) {
                try { pm.getPackageInfo(app, 0); return true } catch (_: Exception) { }
            }

            false
        } catch (_: Exception) { false }
    }

    // ── Screen Mirroring Detection ──
    private fun isScreenMirroring(context: Context): Boolean {
        return try {
            val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
                ?: return false
            // Check for presentation displays (cast/mirror targets)
            dm.displays.any { display ->
                display.displayId != Display.DEFAULT_DISPLAY &&
                    (display.flags and Display.FLAG_PRESENTATION) != 0
            }
        } catch (_: Exception) { false }
    }
}

fun DeviceStatus.hasThreat(): Boolean =
    isRooted || fridaDetected || debuggerAttached || emulatorDetected ||
        hooked || tampered || untrustedInstaller || developerMode ||
        adbEnabled || vpnDetected || envTampering || runtimeIntegrity ||
        proxyDetected || screenRecording || keyloggerRisk || untrustedKeyboard ||
        deviceLockMissing || overlayDetected || malwarePackages.isNotEmpty() ||
        unsecuredWifi || smsForwarderApps.isNotEmpty() || remoteAccessApps.isNotEmpty() ||
        zygiskDetected || anonElfDetected || zygiskFdDetected ||
    timeSpoofing || locationSpoofing || screenMirroring
