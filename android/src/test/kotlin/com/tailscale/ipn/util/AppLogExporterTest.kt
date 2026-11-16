// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AppLogExporterTest {
  @Test
  fun masksWireGuardLinkSecret() {
    val line = "got wireguard://0LDaA9Q3jGHbfgYcWof6ySEicWnTO8OGA4lTkdPSJ2Y%3D@127.0.0.1:59969?publickey=abc"
    val out = AppLogExporter.redact(line)
    assertFalse(out.contains("0LDaA9Q3"))
    assertEquals("got wireguard://xxxxx@127.0.0.1:59969?publickey=abc", out)
  }

  @Test
  fun masksSecretKeyJsonAndAuthKey() {
    val out = AppLogExporter.redact("""{"host":"127.0.0.1","secretKey":"AbC+/=","port":1} tskey-auth-k123-XYZ""")
    assertEquals("""{"host":"127.0.0.1","secretKey":"xxxxx","port":1} tskey-xxxxx""", out)
  }

  @Test
  fun leavesOrdinaryLinesAlone() {
    val line = "magicv2ray: endpoint 127.0.0.1:59969 up, addresses [100.71.129.91/32]"
    assertEquals(line, AppLogExporter.redact(line))
  }

  @Test
  fun fileNameIsTimestampedTxt() {
    val n = AppLogExporter.defaultFileName()
    assertEquals(true, Regex("""Tailscale_logs_\d{8}_\d{6}\.txt""").matches(n))
  }
}
