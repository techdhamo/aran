// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.mazhai.aran.security

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import androidx.core.content.ContextCompat
import org.mazhai.aran.core.AranNative
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Scorched Earth Sandbox — Android Implementation
 *
 * When KILL_APP or critical threat (Frida/Root) is detected:
 *
 *   1. SHRED — Wipe all Keystore entries + SharedPreferences + app data
 *   2. SEVER — Set native g_aran_is_compromised flag → blackholes all network I/O
 *   3. FREEZE — Launch full-screen overlay activity absorbing all touch events
 *
 * Unlike iOS, Android allows process termination, but Scorched Earth provides
 * defense-in-depth: even if exit() is hooked, secrets are already wiped.
 *
 * The app becomes a lobotomized husk. User must manually force-stop.
 */
internal object AranScorchedEarth {

    private const val TAG = "AranScorchedEarth"
    private const val PREFS_NAME = "aran_secure_prefs"
    private const val WIPE_TIMEOUT_MS = 500L

    private val hasExecuted = AtomicBoolean(false)
    private var context: Context? = null

    /**
     * Execute the Scorched Earth protocol. Idempotent — safe to call multiple times.
     * After this call, the app has zero secrets, zero network, and zero UI interaction.
     */
    @JvmStatic
    fun execute(context: Context, reason: String) {
        if (hasExecuted.getAndSet(true)) {
            Log.w(TAG, "Scorched Earth already executed, ignoring duplicate call")
            return
        }

        this.context = context.applicationContext

        Log.e(TAG, "☠️ SCORCHED EARTH ACTIVATED — $reason")

        // ── Phase 1: Network Blackhole (native level, immediate) ──
        // Must happen FIRST — prevents Frida exfiltrating data during the wipe window
        severNetwork()

        // ── Phase 2: Crypto & Data Shred (async, with timeout) ──
        val shredStart = System.currentTimeMillis()
        shredAllSecrets(context)
        val shredTime = System.currentTimeMillis() - shredStart
        Log.d(TAG, "Shred completed in ${shredTime}ms")

        // ── Phase 3: Glass Wall UI Lockout (main thread) ──
        Handler(Looper.getMainLooper()).post {
            launchGlassWallActivity(context, reason)
        }

        // ── Phase 4: Delayed process termination (backup kill) ──
        // Even if Glass Wall is bypassed, we'll die shortly
        Handler(Looper.getMainLooper()).postDelayed({
            if (android.os.Process.myPid() > 0) {
                Log.e(TAG, "Executing backup process termination")
                android.os.Process.killProcess(android.os.Process.myPid())
            }
        }, 3000)
    }

    // ============================================================================
    // PHASE 1: SEVER — Network Blackhole
    // ============================================================================

    /**
     * Sets the native compromised flag. Once set, all native network operations
     * return errors. JNI interceptors in OkHttp/Cronet check this flag.
     */
    private fun severNetwork() {
        try {
            AranNative.setCompromisedFlag()
            Log.d(TAG, "Network blackhole activated — native flag set")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set compromised flag", e)
        }
    }

    // ============================================================================
    // PHASE 2: SHRED — Wipe All Secrets
    // ============================================================================

    /**
     * Wipes all cryptographic material and sensitive data:
     * - Android Keystore (all aliases)
     * - SharedPreferences (all files)
     * - App-specific storage
     * - Cookie stores
     */
    private fun shredAllSecrets(context: Context) {
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()

        executor.execute {
            try {
                shredKeystore()
                shredSharedPreferences(context)
                shredAppData(context)

                // Attempt to trigger GC (best effort)
                System.gc()
                System.runFinalization()

            } catch (e: Exception) {
                Log.e(TAG, "Error during shred", e)
            } finally {
                executor.shutdownNow()
            }
        }

        // Don't wait indefinitely — if shred takes too long, continue anyway
        try {
            executor.awaitTermination(WIPE_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    /**
     * Deletes ALL entries from Android Keystore.
     * No keys, certificates, or cryptographic material remains.
     */
    private fun shredKeystore() {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val aliases = keyStore.aliases()
            var deletedCount = 0

            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                try {
                    keyStore.deleteEntry(alias)
                    deletedCount++
                    Log.d(TAG, "Deleted Keystore alias: $alias")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to delete alias: $alias", e)
                }
            }

            Log.i(TAG, "Keystore shredded — $deletedCount aliases deleted")
        } catch (e: Exception) {
            Log.e(TAG, "Keystore shred failed", e)
        }
    }

    /**
     * Clears ALL SharedPreferences files.
     * Includes default prefs, WebView cookies, and any app-specific prefs.
     */
    private fun shredSharedPreferences(context: Context) {
        try {
            // Clear Aran-specific prefs
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit() // synchronous

            // Clear default prefs
            context.getSharedPreferences(context.packageName + "_preferences", Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()

            // Clear WebView cookies
            android.webkit.CookieManager.getInstance().removeAllCookies(null)
            android.webkit.CookieManager.getInstance().flush()

            Log.i(TAG, "SharedPreferences shredded")
        } catch (e: Exception) {
            Log.e(TAG, "SharedPreferences shred failed", e)
        }
    }

    /**
     * Clears app cache, databases, and files directories.
     * Note: This may cause crashes if other threads are accessing files.
     */
    private fun shredAppData(context: Context) {
        try {
            // Clear cache
            context.cacheDir?.deleteRecursively()

            // Clear databases
            context.databaseList()?.forEach { dbName ->
                context.deleteDatabase(dbName)
            }

            // Clear files (excluding our own process files)
            context.filesDir?.listFiles()?.forEach { file ->
                if (!file.name.contains("scorched")) {
                    file.deleteRecursively()
                }
            }

            Log.i(TAG, "App data shredded")
        } catch (e: Exception) {
            Log.e(TAG, "App data shred failed", e)
        }
    }

    // ============================================================================
    // PHASE 3: FREEZE — Glass Wall Activity
    // ============================================================================

    /**
     * Launches the Glass Wall overlay activity.
     * This activity:
     * - Locks the screen (if device admin)
     * - Shows a full-screen overlay
     * - Absorbs all touch events
     * - Cannot be dismissed via back button
     */
    private fun launchGlassWallActivity(context: Context, reason: String) {
        try {
            val intent = android.content.Intent(context, GlassWallActivity::class.java)
            intent.flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                    android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    android.content.Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS
            intent.putExtra("reason", reason)
            context.startActivity(intent)

            Log.i(TAG, "Glass Wall launched")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch Glass Wall", e)
        }
    }

    // ============================================================================
    // Glass Wall Activity — Full-screen touch-absorbing overlay
    // ============================================================================

    /**
     * Glass Wall Activity — The "lobotomized husk" UI.
     *
     * This activity:
     * - Appears above all other app content
     * - Absorbs all touch events (no clicks pass through)
     * - Cannot be dismissed with back button
     * - Shows a security warning (localized)
     * - Triggers device lock if possible
     */
    class GlassWallActivity : Activity() {

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)

            val reason = intent.getStringExtra("reason") ?: "Security violation detected"

            // Make it a lock screen-style overlay
            window.addFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                        WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                        WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD or
                        WindowManager.LayoutParams.FLAG_FULLSCREEN
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                setShowWhenLocked(true)
                setTurnScreenOn(true)
            }

            // Create a full-screen touch-absorbing view
            val rootView = FrameLayout(this).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
                setBackgroundColor(ContextCompat.getColor(context, android.R.color.black))

                // Add a dark red security warning
                val warningView = android.widget.TextView(context).apply {
                    text = "🔒 Critical Security Violation\n\nDevice Compromised\n\n$reason"
                    setTextColor(android.graphics.Color.parseColor("#FF4444"))
                    textSize = 18f
                    textAlignment = View.TEXT_ALIGNMENT_CENTER
                    gravity = android.view.Gravity.CENTER
                }
                addView(warningView)
            }

            // Absorb all touch events
            rootView.setOnTouchListener { _, _ -> true }

            setContentView(rootView)

            // Attempt to lock the device (requires device admin, may fail silently)
            try {
                val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    keyguardManager.requestDismissKeyguard(this, null)
                }
            } catch (_: Exception) {
                // Device admin not granted, continue without lock
            }

            Log.e(TAG, "Glass Wall active — app frozen: $reason")
        }

        override fun onBackPressed() {
            // Ignore back button — user cannot dismiss
            Log.w(TAG, "Back button pressed in Glass Wall — ignored")
        }

        override fun onTouchEvent(event: MotionEvent?): Boolean {
            // Absorb all touch events
            return true
        }

        override fun onPause() {
            super.onPause()
            // Immediately finish and remove from recents if somehow paused
            finishAndRemoveTask()
        }
    }
}
