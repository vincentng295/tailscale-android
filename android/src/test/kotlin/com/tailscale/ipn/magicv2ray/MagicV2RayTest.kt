// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

import com.tailscale.ipn.magicv2ray.WireGuardUri.Companion.Reason
import com.tailscale.ipn.magicv2ray.WireGuardUri.Companion.Result
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MagicV2RayTest {
  private val warp =
      "wireguard://0LDaA9Q3jGHbfgYcWof6ySEicWnTO8OGA4lTkdPSJ2Y%3D@engage.cloudflareclient.com:2408" +
          "?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&reserved=174%2C133%2C247" +
          "&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A85b4%3A230f%3Acc66%3Aab9a%3A8cde%2F128" +
          "&mtu=1280#WARP"

  @Test
  fun parsesWarpLink() {
    val u = (WireGuardUri.parse(warp) as Result.Ok).uri
    assertEquals("engage.cloudflareclient.com", u.host)
    assertEquals(2408, u.port)
    assertEquals("0LDaA9Q3jGHbfgYcWof6ySEicWnTO8OGA4lTkdPSJ2Y=", u.secretKey)
    assertEquals("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", u.publicKey)
    assertEquals(listOf(174, 133, 247), u.reserved)
    assertEquals(listOf("172.16.0.2/32", "2606:4700:110:85b4:230f:cc66:ab9a:8cde/128"), u.addresses)
    assertEquals(1280, u.mtu)
    assertEquals("WARP", u.name)
  }

  // Same shape as the link libtailscale generates (StartMagicV2RayEndpoint): loopback endpoint,
  // percent-encoded keys, raw comma separated CIDRs, no reserved bytes.
  @Test
  fun parsesLinkGeneratedByLibtailscale() {
    val link =
        "wireguard://0LDaA9Q3jGHbfgYcWof6ySEicWnTO8OGA4lTkdPSJ2Y%3D@127.0.0.1:43210" +
            "?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D" +
            "&address=100.64.1.2/32,fd7a:115c:a1e0::1/128&mtu=1280#Tailscale"
    val u = (WireGuardUri.parse(link) as Result.Ok).uri
    assertEquals("127.0.0.1", u.host)
    assertEquals(43210, u.port)
    assertEquals("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", u.publicKey)
    assertEquals(listOf("100.64.1.2/32", "fd7a:115c:a1e0::1/128"), u.addresses)
    assertTrue(u.reserved.isEmpty())
    assertEquals(1280, u.mtu)
    assertEquals("Tailscale", u.name)
  }

  @Test
  fun rejectsBadLinks() {
    fun reason(s: String) = (WireGuardUri.parse(s) as Result.Error).reason
    assertEquals(Reason.EMPTY, reason("  "))
    assertEquals(Reason.NOT_WIREGUARD_SCHEME, reason("socks://127.0.0.1:4311"))
    assertEquals(Reason.MALFORMED, reason("wireguard://host:1"))
    assertEquals(Reason.BAD_SECRET_KEY, reason(warp.replace("0LDaA9Q3", "short")))
    assertEquals(Reason.BAD_PUBLIC_KEY, reason(warp.replace("publickey=", "x=")))
    assertEquals(Reason.BAD_ENDPOINT, reason(warp.replace(":2408", ":99999")))
    assertEquals(Reason.BAD_RESERVED, reason(warp.replace("174%2C133%2C247", "1%2C2")))
    assertEquals(Reason.BAD_MTU, reason(warp.replace("mtu=1280", "mtu=10")))
  }

  private fun overrides(magicDns: Boolean, exitNode: Boolean, dns: String = "100.100.100.100") =
      """{"traffic":{"sniffing":false,"hijackDns":$magicDns,"foreignDns":"$dns","directDns":"","directDnsDomains":""},"network":{"lanProxyCidrs":"100.64.0.0/10 fc00::/7"},"routing":{"mode":"replace","rules":[{"remarks":"To tailscale","ip":"100.64.0.0/10,fd7a:115c:a1e0::/48","outboundTag":"proxy"},{"remarks":"else direct (ip)","ip":"0.0.0.0/0,::/0","outboundTag":"${if (exitNode) "proxy" else "direct"}"},{"remarks":"else direct (domain)","domain":"regexp:.+","outboundTag":"${if (exitNode) "proxy" else "direct"}"}]}}"""

  @Test
  fun overridesMatchRequestedSettings() {
    assertEquals(overrides(magicDns = true, exitNode = false), MagicV2RayOverrides.json())
    assertEquals(
        overrides(magicDns = false, exitNode = false),
        MagicV2RayOverrides.json(magicDns = false),
    )
    assertEquals(
        overrides(magicDns = true, exitNode = true),
        MagicV2RayOverrides.json(exitNode = true),
    )
    assertEquals(
        overrides(magicDns = true, exitNode = false, dns = "put-tailscale-dns-here"),
        MagicV2RayOverrides.json(tailscaleDns = "put-tailscale-dns-here"),
    )
    assertTrue(MagicV2RayOverrides.json(tailscaleDns = "").contains("\"foreignDns\":\"100.100.100.100\""))
    assertFalse(MagicV2RayOverrides.json(tailscaleDns = "a\"b").contains("a\"b"))
  }
}
