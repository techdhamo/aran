package org.mazhai.aran.util

import android.app.Activity
import android.view.WindowManager

/**
 * Secure Window utility — addresses VAPT findings:
 * - #8 Recent App Exposure (FLAG_SECURE prevents thumbnail in recents)
 * - #7 Screen Mirroring prevention (FLAG_SECURE blocks screenshots/casting)
 * - #23 Screen Recording prevention (FLAG_SECURE blocks screen capture)
 * - #21 Screen mirroring detection not implemented
 *
 * Usage in Activity.onCreate():
 * ```
 * AranSecureWindow.lock(this)
 * ```
 */
object AranSecureWindow {

    fun lock(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    fun unlock(activity: Activity) {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
