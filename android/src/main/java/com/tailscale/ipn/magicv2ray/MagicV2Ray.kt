// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject

/**
 * Client side of the Magic V2Ray external API (Kotlin port of the example app magic-dns-rewrite).
 *
 * - connect: explicit intent `com.huskydg.magicv2ray.action.CONNECT` with extras uri / name /
 *   exclude / overrides. Magic V2Ray always asks the user to confirm; the server of the session is
 *   temporary and the user's own nodes are untouched.
 * - disconnect: `com.huskydg.magicv2ray.action.DISCONNECT`, no confirmation.
 * - info / state: read-only ContentProvider `content://com.huskydg.magicv2ray.api`. Blocking, so
 *   never call it on the main thread.
 * - state events: broadcast `com.huskydg.magicv2ray.event.STATE_CHANGED`.
 *
 * Requires `<queries>` for com.huskydg.magicv2ray in the manifest (Android 11+).
 */
object MagicV2Ray {
  const val PKG = "com.huskydg.magicv2ray"
  const val ACTION_CONNECT = "com.huskydg.magicv2ray.action.CONNECT"
  const val ACTION_DISCONNECT = "com.huskydg.magicv2ray.action.DISCONNECT"
  const val EVENT_STATE_CHANGED = "com.huskydg.magicv2ray.event.STATE_CHANGED"
  private const val AUTHORITY = "com.huskydg.magicv2ray.api"

  /** Name shown by Magic V2Ray (status chip, notification) while our session runs. */
  const val SESSION_NAME = "Tailscale"

  data class Info(
      val installed: Boolean = false,
      val versionName: String = "",
      val apiLevel: Int = 0,
      val mode: String = "",
      val connected: Boolean = false,
      val stateKnown: Boolean = false,
      val sessionActive: Boolean = false,
      val sessionName: String = "",
      val features: Set<String> = emptySet(),
  ) {
    val supportsOverrides: Boolean
      get() = "overrides" in features
  }

  data class StateEvent(
      val connected: Boolean,
      val reason: String,
      val session: Boolean,
      val sessionName: String,
      val caller: String,
      val seq: Long,
      val time: Long,
  )

  /** True if Magic V2Ray is installed and knows the connect API. Fine on the main thread. */
  fun isAvailable(context: Context): Boolean {
    val i = Intent(ACTION_CONNECT).setPackage(PKG)
    return i.resolveActivity(context.packageManager) != null
  }

  /** Version, API level and state. BLOCKS: call from a background thread. Never throws. */
  fun info(context: Context): Info {
    val version =
        try {
          context.packageManager.getPackageInfo(PKG, 0).versionName ?: ""
        } catch (e: PackageManager.NameNotFoundException) {
          return Info()
        }
    val bundle: android.os.Bundle? =
        try {
          context.contentResolver.call(
              android.net.Uri.parse("content://$AUTHORITY"),
              "getInfo",
              null,
              null,
          )
        } catch (e: RuntimeException) {
          null
        }
    if (bundle == null) return Info(installed = true, versionName = version)
    return try {
      val j = JSONObject(bundle.getString("json", "{}"))
      val api = j.optJSONObject("api")
      val st = j.optJSONObject("state")
      val session = st?.optJSONObject("session")
      val features = HashSet<String>()
      api?.optJSONArray("features")?.let { a ->
        for (n in 0 until a.length()) features.add(a.optString(n))
      }
      Info(
          installed = true,
          versionName = j.optString("versionName", version),
          apiLevel = api?.optInt("level") ?: 0,
          mode = j.optString("mode"),
          connected = st?.optBoolean("connected") ?: false,
          stateKnown = st?.optBoolean("known") ?: false,
          sessionActive = session?.optBoolean("active") ?: false,
          sessionName = session?.optString("name") ?: "",
          features = features,
      )
    } catch (e: Exception) {
      Info(installed = true, versionName = version)
    }
  }

  /**
   * Asks Magic V2Ray to route the device through [uri] (a wireguard:// link, passed directly, no
   * SOCKS hop) with the temporary [overridesJson]. The user confirms in Magic V2Ray.
   *
   * @return false if Magic V2Ray is not installed / too old to resolve the intent.
   */
  fun connect(activity: Activity, uri: String, overridesJson: String): Boolean {
    val intent =
        Intent(ACTION_CONNECT)
            .setPackage(PKG)
            .putExtra("uri", uri)
            .putExtra("name", SESSION_NAME)
            .putExtra("overrides", overridesJson)
    return start(activity, intent)
  }

  /** Ends the session (the user's own node comes back). No confirmation. */
  fun disconnect(activity: Activity): Boolean = start(activity, Intent(ACTION_DISCONNECT).setPackage(PKG))

  private fun start(activity: Activity, intent: Intent): Boolean =
      try {
        activity.startActivity(intent)
        true
      } catch (e: ActivityNotFoundException) {
        false
      }

  fun parse(i: Intent?): StateEvent? {
    if (i == null || i.action != EVENT_STATE_CHANGED) return null
    return StateEvent(
        connected = i.getBooleanExtra("connected", false),
        reason = i.getStringExtra("reason") ?: "",
        session = i.getBooleanExtra("session", false),
        sessionName = i.getStringExtra("sessionName") ?: "",
        caller = i.getStringExtra("caller") ?: "",
        seq = i.getLongExtra("seq", 0),
        time = i.getLongExtra("time", 0),
    )
  }

  /** Listens for state events (duplicates dropped). Callback runs on the main thread. */
  fun listen(context: Context, onState: (StateEvent) -> Unit): BroadcastReceiver {
    val receiver =
        object : BroadcastReceiver() {
          private var lastSeq = -1L
          private var lastTime = -1L

          override fun onReceive(c: Context, i: Intent) {
            val e = parse(i) ?: return
            if (e.seq == lastSeq && e.time == lastTime) return
            lastSeq = e.seq
            lastTime = e.time
            onState(e)
          }
        }
    val filter = IntentFilter(EVENT_STATE_CHANGED)
    if (Build.VERSION.SDK_INT >= 33) {
      context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
    } else {
      @Suppress("UnspecifiedRegisterReceiverFlag") context.registerReceiver(receiver, filter)
    }
    return receiver
  }

  fun unlisten(context: Context, receiver: BroadcastReceiver?) {
    if (receiver == null) return
    try {
      context.unregisterReceiver(receiver)
    } catch (e: IllegalArgumentException) {
      // already unregistered
    }
  }
}
