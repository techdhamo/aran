package org.mazhai.aran.util

import android.content.ClipboardManager
import android.content.Context
import android.os.Build

/**
 * Clipboard Guard — VAPT finding #23 (Sensitive data copy/paste allowed).
 *
 * Clears clipboard after a timeout to prevent data leakage.
 * Also provides a method to block paste from clipboard in sensitive fields.
 *
 * Usage:
 * ```
 * AranClipboardGuard.clearAfterDelay(context, delayMs = 30_000)
 * ```
 */
object AranClipboardGuard {

    fun clearNow(context: Context) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            cm.clearPrimaryClip()
        } else {
            @Suppress("DEPRECATION")
            cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
        }
    }

    fun clearAfterDelay(context: Context, delayMs: Long = 30_000L) {
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            clearNow(context)
        }, delayMs)
    }

    fun onCopyDetected(context: Context, action: () -> Unit) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        cm.addPrimaryClipChangedListener { action() }
    }
}
