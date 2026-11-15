// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

import com.tailscale.ipn.UninitializedApp
import com.tailscale.ipn.ui.notifier.Notifier
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * "Working mode" setting: VpnService (default) or Magic V2Ray.
 *
 * - The mode flag lives in the unencrypted preferences of [UninitializedApp] so receivers, the quick
 *   settings tile and IPNService can read it without initializing the whole app.
 * - There is no WireGuard link setting: in Magic V2Ray mode the link (with fresh keys) is generated
 *   by libtailscale each time ([MagicV2RayController]) and never stored.
 * - [pending] is the hand-off to MainActivity: Magic V2Ray can only be started from a foreground
 *   Activity, so connect / disconnect requests wait there until an Activity is visible.
 */
object MagicV2RaySettings {
  /** True when the working mode is Magic V2Ray, false for VpnService. */
  private val _enabled = MutableStateFlow(UninitializedApp.get().isMagicV2RayMode())
  val enabled: StateFlow<Boolean> = _enabled.asStateFlow()

  fun setEnabled(on: Boolean) {
    UninitializedApp.get().setMagicV2RayMode(on)
    _enabled.value = on
  }

  /** What MainActivity should do with Magic V2Ray. Held in memory only (the URI has a secret). */
  sealed class Pending {
    data class Connect(val uri: String, val overridesJson: String) : Pending()

    data object Disconnect : Pending()
  }

  private val _pending = MutableStateFlow<Pending?>(null)
  val pending: StateFlow<Pending?> = _pending.asStateFlow()

  /** True while Magic V2Ray reports a connected session started by us. */
  private val _sessionConnected = MutableStateFlow(false)
  val sessionConnected: StateFlow<Boolean> = _sessionConnected.asStateFlow()

  fun setSessionConnected(connected: Boolean) {
    _sessionConnected.value = connected
  }

  /**
   * The temporary overrides JSON for the connect request. MagicDNS follows the "Use Tailscale DNS
   * settings" pref and the exit node follows the selected exit node, both as of connect time.
   */
  fun overridesJson(): String {
    val prefs = Notifier.prefs.value
    return MagicV2RayOverrides.json(
        magicDns = prefs?.CorpDNS ?: true,
        exitNode = prefs?.activeExitNodeID != null,
    )
  }

  fun post(p: Pending) {
    _pending.value = p
  }

  /** Marks [p] as handled (no-op if a newer request replaced it). */
  fun consume(p: Pending) {
    _pending.compareAndSet(p, null)
  }
}
