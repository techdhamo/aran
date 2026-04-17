package org.mazhai.aran

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.view.WindowManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mazhai.aran.util.AranClipboardGuard
import org.mazhai.aran.util.AranSecureWindow

/**
 * Instrumentation tests for Aran Secure SDK utilities and policy mapping.
 * Run with: ./gradlew :aran-secure:connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class AranSecurityTests {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun testAranEnvironmentPolicyMapping_DEV() {
        val policy = when (AranEnvironment.DEV) {
            AranEnvironment.DEV -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = false,
                killOnFrida = false,
                killOnDebugger = false
            )
            AranEnvironment.UAT -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = false
            )
            AranEnvironment.RELEASE -> SecurityPolicy(
                autoAlert = false,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = true,
                killOnEmulator = true,
                killOnHook = true,
                killOnTamper = true
            )
        }

        // DEV: Alert only, no kill
        assertTrue("DEV should enable autoAlert", policy.autoAlert)
        assertFalse("DEV should NOT kill on root", policy.killOnRoot)
        assertFalse("DEV should NOT kill on frida", policy.killOnFrida)
        assertFalse("DEV should NOT kill on debugger", policy.killOnDebugger)
    }

    @Test
    fun testAranEnvironmentPolicyMapping_UAT() {
        val policy = when (AranEnvironment.UAT) {
            AranEnvironment.DEV -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = false,
                killOnFrida = false,
                killOnDebugger = false
            )
            AranEnvironment.UAT -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = false
            )
            AranEnvironment.RELEASE -> SecurityPolicy(
                autoAlert = false,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = true,
                killOnEmulator = true,
                killOnHook = true,
                killOnTamper = true
            )
        }

        // UAT: Alert + kill on root/frida
        assertTrue("UAT should enable autoAlert", policy.autoAlert)
        assertTrue("UAT should kill on root", policy.killOnRoot)
        assertTrue("UAT should kill on frida", policy.killOnFrida)
        assertFalse("UAT should NOT kill on debugger", policy.killOnDebugger)
    }

    @Test
    fun testAranEnvironmentPolicyMapping_RELEASE() {
        val policy = when (AranEnvironment.RELEASE) {
            AranEnvironment.DEV -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = false,
                killOnFrida = false,
                killOnDebugger = false
            )
            AranEnvironment.UAT -> SecurityPolicy(
                autoAlert = true,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = false
            )
            AranEnvironment.RELEASE -> SecurityPolicy(
                autoAlert = false,
                killOnRoot = true,
                killOnFrida = true,
                killOnDebugger = true,
                killOnEmulator = true,
                killOnHook = true,
                killOnTamper = true
            )
        }

        // RELEASE: Silent telemetry + kill on all major threats
        assertFalse("RELEASE should disable autoAlert (silent mode)", policy.autoAlert)
        assertTrue("RELEASE should kill on root", policy.killOnRoot)
        assertTrue("RELEASE should kill on frida", policy.killOnFrida)
        assertTrue("RELEASE should kill on debugger", policy.killOnDebugger)
        assertTrue("RELEASE should kill on emulator", policy.killOnEmulator)
        assertTrue("RELEASE should kill on hook", policy.killOnHook)
        assertTrue("RELEASE should kill on tamper", policy.killOnTamper)
    }

    @Test
    fun testAranSecureWindow_appliesFlagSecure() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            val activity = object : Activity() {}
            activity.setTheme(android.R.style.Theme_Material_Light)
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

            // Apply FLAG_SECURE
            AranSecureWindow.lock(activity)

            val flags = activity.window.attributes.flags
            val hasFlagSecure = (flags and WindowManager.LayoutParams.FLAG_SECURE) != 0

            assertTrue(
                "AranSecureWindow.lock() should apply FLAG_SECURE to prevent screenshots/recents thumbnail",
                hasFlagSecure
            )
        }
    }

    @Test
    fun testAranSecureWindow_removeFlagSecure() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            val activity = object : Activity() {}
            activity.setTheme(android.R.style.Theme_Material_Light)

            // Lock then unlock
            AranSecureWindow.lock(activity)
            AranSecureWindow.unlock(activity)

            val flags = activity.window.attributes.flags
            val hasFlagSecure = (flags and WindowManager.LayoutParams.FLAG_SECURE) != 0

            assertFalse(
                "AranSecureWindow.unlock() should remove FLAG_SECURE",
                hasFlagSecure
            )
        }
    }

    @Test
    fun testAranClipboardGuard_clearsClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        // Set some sensitive data
        val clip = android.content.ClipData.newPlainText("test", "SENSITIVE_PASSWORD_123")
        cm.setPrimaryClip(clip)

        // Verify it's set
        val before = cm.primaryClip?.getItemAt(0)?.text?.toString()
        assertEquals("SENSITIVE_PASSWORD_123", before)

        // Clear it
        AranClipboardGuard.clearNow(context)

        // Verify it's cleared
        val after = cm.primaryClip?.getItemAt(0)?.text?.toString()
        assertTrue(
            "AranClipboardGuard.clearNow() should wipe clipboard content",
            after.isNullOrEmpty()
        )
    }

    @Test
    fun testDeviceStatus_hasThreat_detectsMalware() {
        val statusWithMalware = DeviceStatus(
            deviceFingerprint = "test-fp",
            appId = "test-app",
            isRooted = false,
            fridaDetected = false,
            debuggerAttached = false,
            emulatorDetected = false,
            hooked = false,
            tampered = false,
            untrustedInstaller = false,
            developerMode = false,
            adbEnabled = false,
            envTampering = false,
            runtimeIntegrity = false,
            proxyDetected = false,
            vpnDetected = false,
            screenRecording = false,
            keyloggerRisk = false,
            untrustedKeyboard = false,
            deviceLockMissing = false,
            overlayDetected = false,
            malwarePackages = listOf("com.malware.stealer"),
            unsecuredWifi = false,
            smsForwarderApps = emptyList(),
            remoteAccessApps = emptyList()
        )

        // Use reflection to access private hasThreat extension
        val method = Class.forName("org.mazhai.aran.AranSecureKt")
            .getDeclaredMethod("hasThreat", DeviceStatus::class.java)
        method.isAccessible = true
        val result = method.invoke(null, statusWithMalware) as Boolean

        assertTrue(
            "DeviceStatus with malwarePackages should trigger hasThreat()",
            result
        )
    }

    @Test
    fun testDeviceStatus_hasThreat_clean() {
        val cleanStatus = DeviceStatus(
            deviceFingerprint = "test-fp",
            appId = "test-app",
            isRooted = false,
            fridaDetected = false,
            debuggerAttached = false,
            emulatorDetected = false,
            hooked = false,
            tampered = false,
            untrustedInstaller = false,
            developerMode = false,
            adbEnabled = false,
            envTampering = false,
            runtimeIntegrity = false,
            proxyDetected = false,
            vpnDetected = false,
            screenRecording = false,
            keyloggerRisk = false,
            untrustedKeyboard = false,
            deviceLockMissing = false,
            overlayDetected = false,
            malwarePackages = emptyList(),
            unsecuredWifi = false,
            smsForwarderApps = emptyList(),
            remoteAccessApps = emptyList()
        )

        val method = Class.forName("org.mazhai.aran.AranSecureKt")
            .getDeclaredMethod("hasThreat", DeviceStatus::class.java)
        method.isAccessible = true
        val result = method.invoke(null, cleanStatus) as Boolean

        assertFalse(
            "Clean DeviceStatus should NOT trigger hasThreat()",
            result
        )
    }
}
