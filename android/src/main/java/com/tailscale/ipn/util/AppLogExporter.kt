// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.util

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Process
import com.tailscale.ipn.magicv2ray.MagicV2RaySettings
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.util.AppVersion
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Exports this app's own log (logcat of this process, which also carries the Go side: `libtailscale`
 * and the Magic V2Ray endpoint lines `magicv2ray:` / `magicv2ray-wg:`) to a file the person picks.
 *
 * No permission is needed: an app can always read its own process' logcat. Secrets are masked
 * before anything is written, see [redact].
 */
object AppLogExporter {
  private const val TAG = "AppLogExporter"

  fun defaultFileName(now: Date = Date()): String =
      "Tailscale_logs_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(now) + ".txt"

  private val wireGuardLink = Regex("""wireguard://[^@\s"'<>]+@""")
  private val secretKeyJson = Regex(""""secretKey"\s*:\s*"[^"]*"""")
  private val authKey = Regex("""tskey-[A-Za-z0-9_-]+""")

  /** Masks WireGuard link secrets, `secretKey` JSON values and Tailscale auth keys. */
  fun redact(text: String): String =
      text
          .replace(wireGuardLink, "wireguard://xxxxx@")
          .replace(secretKeyJson, "\"secretKey\":\"xxxxx\"")
          .replace(authKey, "tskey-xxxxx")

  fun header(
      version: String,
      state: String,
      magicMode: Boolean,
      now: Date = Date(),
  ): String =
      buildString {
        appendLine("Tailscale - app log")
        appendLine("Secrets (WireGuard keys, auth keys) are replaced with xxxxx.")
        appendLine()
        appendLine("Exported: $now")
        appendLine("App version: $version")
        appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
        appendLine("Magic V2Ray mode: ${if (magicMode) "ON" else "OFF"}")
        appendLine("Tailscale state: $state")
        appendLine()
        appendLine("=== logcat (this process) ===")
      }

  /** Dumps this process' logcat into [uri]. Blocking: call it off the main thread. */
  fun write(context: Context, uri: Uri): Boolean {
    return try {
      val state = Notifier.state.value.name
      val head =
          header(
              version = AppVersion.Short(),
              state = state,
              magicMode = MagicV2RaySettings.enabled.value,
          )
      val proc =
          ProcessBuilder("logcat", "-d", "-v", "threadtime", "--pid=${Process.myPid()}")
              .redirectErrorStream(true)
              .start()
      val out =
          context.contentResolver.openOutputStream(uri, "wt")
              ?: return false.also { proc.destroy() }
      out.bufferedWriter().use { w ->
        w.write(head)
        proc.inputStream.bufferedReader().useLines { lines ->
          lines.forEach {
            w.write(redact(it))
            w.newLine()
          }
        }
      }
      proc.waitFor()
      true
    } catch (e: Exception) {
      TSLog.e(TAG, "export failed: $e")
      false
    }
  }
}
