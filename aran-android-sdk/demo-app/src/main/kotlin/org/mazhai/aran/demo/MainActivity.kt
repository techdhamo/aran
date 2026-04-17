package org.mazhai.aran.demo

import android.app.AlertDialog
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.mazhai.aran.AranEnvironment
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranThreatListener
import org.mazhai.aran.DeviceStatus

class MainActivity : AppCompatActivity() {

    private var simulationMode: SimulationMode = SimulationMode.NONE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        AranSecure.start(
            context = this,
            licenseKey = "DEMO_LIC_123",
            expectedSignatureSha256 = "EXPECTED_SHA256_HEX",
            environment = AranEnvironment.DEV,
            listener = object : AranThreatListener {
                override fun onThreatDetected(status: DeviceStatus, reactionPolicy: String) {
                    runOnUiThread {
                        // Change background to dark red
                        window.decorView.setBackgroundColor(0xFFB71C1C.toInt())
                        
                        // Update status text with custom warning
                        val statusText = findViewById<TextView>(R.id.statusText)
                        statusText.text = buildString {
                            append("⚠️ HOST APP INTERCEPTED THREAT ⚠️\n\n")
                            append("Reaction Policy: $reactionPolicy\n\n")
                            append("The host application has taken control of threat handling.\n")
                            append("This demonstrates CUSTOM policy delegation.\n\n")
                            append("── Threat Details ──\n")
                            if (status.isRooted) append("• Device is ROOTED\n")
                            if (status.fridaDetected) append("• Frida DETECTED\n")
                            if (status.debuggerAttached) append("• Debugger ATTACHED\n")
                            if (status.emulatorDetected) append("• Running on EMULATOR\n")
                            if (status.hooked) append("• App is HOOKED\n")
                            if (status.tampered) append("• APK TAMPERED\n")
                            if (status.malwarePackages.isNotEmpty()) {
                                append("• Malware: ${status.malwarePackages.size} app(s)\n")
                                status.malwarePackages.forEach { append("  → $it\n") }
                            }
                            append("\nApp continues running with custom UI.\n")
                            append("No default dialog. No app termination.\n")
                        }
                        
                        // Show custom alert
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("🛡️ Custom Threat Handler")
                            .setMessage("Your organization's security policy has intercepted this threat. The app will continue running in restricted mode.")
                            .setPositiveButton("Acknowledge", null)
                            .show()
                    }
                }
            }
        )

        val statusText = findViewById<TextView>(R.id.statusText)
        findViewById<Button>(R.id.scanButton).setOnClickListener {
            val status = if (simulationMode != SimulationMode.NONE) {
                simulateThreats(AranSecure.checkEnvironment())
            } else {
                AranSecure.checkEnvironment()
            }

            statusText.text = buildString {
                append("── Aran Secure · Threat Profile ──\n\n")
                
                // Cloud-Managed RASP Sync Info
                val lastSync = AranSecure.getLastSyncTimestamp()
                val requestId = AranSecure.getCurrentRequestId()
                if (lastSync > 0) {
                    val syncAgo = (System.currentTimeMillis() - lastSync) / 1000
                    append("☁️ Last Cloud Sync: ${syncAgo}s ago\n")
                } else {
                    append("☁️ Last Cloud Sync: Pending...\n")
                }
                if (requestId.isNotEmpty()) {
                    append("🔍 Active Request ID: ${requestId.take(8)}…\n")
                }
                append("\n")
                
                if (simulationMode != SimulationMode.NONE) {
                    append("[PENTEST MODE: ${simulationMode.name}]\n\n")
                }
                append("fp: ${status.deviceFingerprint.take(12)}…\n\n")
                append("── Native (C++) ──\n")
                append("rooted:       ${flag(status.isRooted)}\n")
                append("frida:        ${flag(status.fridaDetected)}\n")
                append("debugger:     ${flag(status.debuggerAttached)}\n")
                append("emulator:     ${flag(status.emulatorDetected)}\n")
                append("hooked:       ${flag(status.hooked)}\n")
                append("tampered:     ${flag(status.tampered)}\n")
                append("untrusted:    ${flag(status.untrustedInstaller)}\n")
                append("dev_mode:     ${flag(status.developerMode)}\n")
                append("adb:          ${flag(status.adbEnabled)}\n")
                append("env_tamper:   ${flag(status.envTampering)}\n")
                append("rt_integrity: ${flag(status.runtimeIntegrity)}\n")
                append("proxy:        ${flag(status.proxyDetected)}\n\n")
                append("── Kotlin ──\n")
                append("vpn:          ${flag(status.vpnDetected)}\n")
                append("screen_rec:   ${flag(status.screenRecording)}\n")
                append("keylogger:    ${flag(status.keyloggerRisk)}\n")
                append("bad_keyboard: ${flag(status.untrustedKeyboard)}\n")
                append("no_lock:      ${flag(status.deviceLockMissing)}\n")
                append("overlay:      ${flag(status.overlayDetected)}\n")
                if (status.malwarePackages.isNotEmpty()) {
                    append("malware:      ⚠ ${status.malwarePackages.size} HARMFUL APP(S)\n")
                    status.malwarePackages.forEach { append("  → $it\n") }
                } else {
                    append("malware:      ✓ CLEAR\n")
                }
                append("wifi_open:    ${flag(status.unsecuredWifi)}\n")
                if (status.smsForwarderApps.isNotEmpty()) {
                    append("sms_fwd:      ⚠ ${status.smsForwarderApps.size} APP(S)\n")
                    status.smsForwarderApps.forEach { append("  → $it\n") }
                } else {
                    append("sms_fwd:      ✓ CLEAR\n")
                }
                if (status.remoteAccessApps.isNotEmpty()) {
                    append("remote_acc:   ⚠ ${status.remoteAccessApps.size} APP(S)\n")
                    status.remoteAccessApps.forEach { append("  → $it\n") }
                } else {
                    append("remote_acc:   ✓ CLEAR\n")
                }
            }

            // Pass "CUSTOM" to test delegation, or "DEFAULT" for normal behavior
            AranSecure.handleThreats(this, status, "CUSTOM")
        }

        // Pentest simulation buttons
        findViewById<Button>(R.id.simulateFridaButton).setOnClickListener {
            simulationMode = SimulationMode.FRIDA
            showPentestAlert("Frida Injection Simulated", "Next scan will show frida_detected = true")
        }

        findViewById<Button>(R.id.simulateMalwareButton).setOnClickListener {
            simulationMode = SimulationMode.MALWARE
            showPentestAlert("Malware Presence Simulated", "Next scan will show 2 harmful packages")
        }

        findViewById<Button>(R.id.simulateTamperButton).setOnClickListener {
            simulationMode = SimulationMode.TAMPER
            showPentestAlert("Tampered Signature Simulated", "Next scan will show tamper_detected = true")
        }

        findViewById<Button>(R.id.clearSimulationButton).setOnClickListener {
            simulationMode = SimulationMode.NONE
            showPentestAlert("Simulation Cleared", "Next scan will show real device status")
        }
    }

    private fun simulateThreats(real: DeviceStatus): DeviceStatus {
        return when (simulationMode) {
            SimulationMode.FRIDA -> real.copy(fridaDetected = true)
            SimulationMode.MALWARE -> real.copy(
                malwarePackages = listOf("com.malware.stealer", "com.fake.trojan")
            )
            SimulationMode.TAMPER -> real.copy(tampered = true)
            SimulationMode.NONE -> real
        }
    }

    private fun showPentestAlert(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle("🧪 $title")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun flag(v: Boolean) = if (v) "⚠ DETECTED" else "✓ CLEAR"

    enum class SimulationMode {
        NONE, FRIDA, MALWARE, TAMPER
    }
}
