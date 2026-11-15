// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

/**
 * Builds the temporary `overrides` JSON sent with the Magic V2Ray connect request. Magic V2Ray
 * applies it to a copy of its own settings for the length of the session and never saves it.
 *
 * - `traffic`: no domain sniffing (not needed), DNS is hijacked only while MagicDNS is on
 *   (`hijackDns = magicDns`) and `foreignDns` points at Tailscale's resolver; `directDns` /
 *   `directDnsDomains` are cleared.
 * - `network.lanProxyCidrs` must be exactly [LAN_PROXY_CIDRS].
 * - `routing` (mode `replace`): tailnet ranges go to `proxy`; everything else (IP and domain) goes
 *   to `direct`, or to `proxy` when an exit node is enabled.
 *
 * Built by hand so it can be unit tested on the JVM (org.json is only a stub there).
 */
object MagicV2RayOverrides {
  /** Tailscale's MagicDNS resolver address. */
  const val DEFAULT_TAILSCALE_DNS = "100.100.100.100"

  /**
   * Must match exactly: the tailnet (CGNAT) range and the Tailscale ULA range. SPACE separated: per
   * the overrides API each entry must be one of Magic V2Ray's built-in ranges, a comma form is
   * ignored silently.
   */
  const val LAN_PROXY_CIDRS = "100.64.0.0/10 fc00::/7"

  /** Tailnet IPv4 + IPv6 ranges routed to the proxy outbound. */
  const val TAILNET_ROUTE_CIDRS = "100.64.0.0/10,fd7a:115c:a1e0::/48"

  fun json(
      magicDns: Boolean = true,
      exitNode: Boolean = false,
      tailscaleDns: String = DEFAULT_TAILSCALE_DNS,
  ): String {
    val dns = tailscaleDns.trim().ifEmpty { DEFAULT_TAILSCALE_DNS }
    val rest = if (exitNode) "proxy" else "direct"
    return """{"traffic":{"sniffing":false,"hijackDns":$magicDns,"foreignDns":${quote(dns)},"directDns":"","directDnsDomains":""},""" +
        """"network":{"lanProxyCidrs":${quote(LAN_PROXY_CIDRS)}},""" +
        """"routing":{"mode":"replace","rules":[""" +
        """{"remarks":"To tailscale","ip":${quote(TAILNET_ROUTE_CIDRS)},"outboundTag":"proxy"},""" +
        """{"remarks":"else direct (ip)","ip":"0.0.0.0/0,::/0","outboundTag":"$rest"},""" +
        """{"remarks":"else direct (domain)","domain":"regexp:.+","outboundTag":"$rest"}""" +
        """]}}"""
  }

  private fun quote(s: String): String {
    val sb = StringBuilder("\"")
    for (c in s) {
      when {
        c == '"' -> sb.append("\\\"")
        c == '\\' -> sb.append("\\\\")
        c < ' ' -> sb.append(String.format("\\u%04x", c.code))
        else -> sb.append(c)
      }
    }
    return sb.append('"').toString()
  }
}
