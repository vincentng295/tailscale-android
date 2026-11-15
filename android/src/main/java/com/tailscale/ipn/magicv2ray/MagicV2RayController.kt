// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

import android.content.BroadcastReceiver
import com.tailscale.ipn.App
import com.tailscale.ipn.UninitializedApp
import com.tailscale.ipn.ui.model.Ipn
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Drives "Magic V2Ray" working mode (no VpnService):
 *
 * start: foreground notification -> WantRunning=true -> wait until Tailscale is Running -> ask
 * libtailscale for the local WireGuard endpoint (it returns the finished `wireguard://` link) ->
 * hand the link to Magic V2Ray ([MagicV2RaySettings.pending], consumed by MainActivity).
 *
 * stop: ask Magic V2Ray to disconnect, then stop the local endpoint.
 *
 * [UninitializedApp.startVPN] / [UninitializedApp.stopVPN] route here when the mode is on, so every
 * entry point (toggle, quick tile, automation intents) behaves the same.
 */
object MagicV2RayController {
  private const val TAG = "MagicV2RayController"
  private const val ENDPOINT_RETRIES = 15
  private const val ENDPOINT_RETRY_DELAY_MS = 1000L

  private var job: Job? = null
  private var receiver: BroadcastReceiver? = null

  fun isMagicMode(): Boolean = UninitializedApp.get().isMagicV2RayMode()

  @Synchronized
  fun start() {
    val app = App.get()
    job?.cancel()
    if (receiver == null) {
      // Tells the UI whether Magic V2Ray really is connected ("Connected • Magic V2Ray").
      receiver =
          MagicV2Ray.listen(app) { e ->
            MagicV2RaySettings.setSessionConnected(e.connected && e.session)
          }
    }
    app.startForegroundForLogin() // keeps the process alive; creates no VPN tunnel
    app.setWantRunning(true)
    job =
        app.applicationScope.launch {
          // Needs the tailnet addresses, which exist from Starting/Running on.
          Notifier.state.first { it == Ipn.State.Running }
          val uri = withContext(Dispatchers.IO) { startEndpoint(app) }
          if (uri == null) {
            TSLog.e(TAG, "could not start the local WireGuard endpoint")
            return@launch
          }
          if (!WireGuardUri.isValid(uri)) {
            // Never expected: the Go side builds a link this parser accepts.
            TSLog.e(TAG, "generated link is not a valid wireguard:// link")
            return@launch
          }
          MagicV2RaySettings.post(
              MagicV2RaySettings.Pending.Connect(uri, MagicV2RaySettings.overridesJson())
          )
          // Tailscale went away (logout, key expiry, stopped elsewhere): end the session too.
          Notifier.state.first { it <= Ipn.State.Stopped }
          endSessions(app)
        }
  }

  @Synchronized
  fun stop() {
    job?.cancel()
    job = null
    endSessions(App.get())
  }

  private fun endSessions(app: App) {
    MagicV2Ray.unlisten(app, receiver)
    receiver = null
    MagicV2RaySettings.setSessionConnected(false)
    MagicV2RaySettings.post(MagicV2RaySettings.Pending.Disconnect)
    app.applicationScope.launch(Dispatchers.IO) {
      try {
        app.getLibtailscaleApp().stopMagicV2RayEndpoint()
      } catch (e: Exception) {
        TSLog.e(TAG, "stopMagicV2RayEndpoint: $e")
      }
    }
  }

  private suspend fun startEndpoint(app: App): String? {
    repeat(ENDPOINT_RETRIES) {
      try {
        return app.getLibtailscaleApp().startMagicV2RayEndpoint()
      } catch (e: Exception) {
        TSLog.d(TAG, "startMagicV2RayEndpoint: $e")
        delay(ENDPOINT_RETRY_DELAY_MS)
      }
    }
    return null
  }
}
