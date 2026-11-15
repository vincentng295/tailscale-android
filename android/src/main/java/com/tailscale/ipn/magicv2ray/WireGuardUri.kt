// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.magicv2ray

import java.net.URLDecoder
import java.util.Base64

/**
 * Parser/validator for the V2Ray-style WireGuard share link that Magic V2Ray understands:
 *
 * wireguard://<secretKey>@<host>:<port>?publickey=<key>&reserved=1,2,3&address=<cidr,cidr>&mtu=1280#name
 *
 * The link is passed to Magic V2Ray unchanged (it is the `uri` of the connect API, no SOCKS
 * indirection); this class only checks that it is well formed so the user gets an error here
 * instead of a silent failure inside Magic V2Ray. Pure Kotlin, no Android dependency.
 */
data class WireGuardUri(
    val secretKey: String,
    val host: String,
    val port: Int,
    val publicKey: String,
    val reserved: List<Int>,
    val addresses: List<String>,
    val mtu: Int?,
    val name: String,
) {
  companion object {
    sealed class Result {
      data class Ok(val uri: WireGuardUri) : Result()

      data class Error(val reason: Reason) : Result()
    }

    enum class Reason {
      EMPTY,
      NOT_WIREGUARD_SCHEME,
      MALFORMED,
      BAD_SECRET_KEY,
      BAD_PUBLIC_KEY,
      BAD_ENDPOINT,
      BAD_RESERVED,
      BAD_MTU,
    }

    private val SCHEMES = listOf("wireguard://", "wg://")

    fun parse(raw: String): Result {
      val text = raw.trim()
      if (text.isEmpty()) return Result.Error(Reason.EMPTY)
      val scheme = SCHEMES.firstOrNull { text.startsWith(it, ignoreCase = true) }
          ?: return Result.Error(Reason.NOT_WIREGUARD_SCHEME)

      var rest = text.substring(scheme.length)
      var name = ""
      rest.indexOf('#').let {
        if (it >= 0) {
          name = decode(rest.substring(it + 1))
          rest = rest.substring(0, it)
        }
      }
      var query = ""
      rest.indexOf('?').let {
        if (it >= 0) {
          query = rest.substring(it + 1)
          rest = rest.substring(0, it)
        }
      }
      rest = rest.trimEnd('/')

      val at = rest.lastIndexOf('@')
      if (at <= 0) return Result.Error(Reason.MALFORMED)
      val secret = decode(rest.substring(0, at))
      val endpoint = rest.substring(at + 1)

      val (host, port) = splitHostPort(endpoint) ?: return Result.Error(Reason.BAD_ENDPOINT)
      if (!isKey(secret)) return Result.Error(Reason.BAD_SECRET_KEY)

      val params = HashMap<String, String>()
      for (pair in query.split('&')) {
        if (pair.isEmpty()) continue
        val eq = pair.indexOf('=')
        val k = decode(if (eq >= 0) pair.substring(0, eq) else pair).lowercase()
        val v = if (eq >= 0) decode(pair.substring(eq + 1)) else ""
        params[k] = v
      }

      val publicKey = params["publickey"] ?: params["public_key"] ?: ""
      if (!isKey(publicKey)) return Result.Error(Reason.BAD_PUBLIC_KEY)

      val reserved = ArrayList<Int>()
      val reservedText = params["reserved"].orEmpty()
      if (reservedText.isNotBlank()) {
        for (part in reservedText.split(',')) {
          val n = part.trim().toIntOrNull()
          if (n == null || n !in 0..255) return Result.Error(Reason.BAD_RESERVED)
          reserved.add(n)
        }
        if (reserved.size != 3) return Result.Error(Reason.BAD_RESERVED)
      }

      var mtu: Int? = null
      val mtuText = params["mtu"]?.trim().orEmpty()
      if (mtuText.isNotEmpty()) {
        val value = mtuText.toIntOrNull()
        if (value == null || value !in 576..1500) return Result.Error(Reason.BAD_MTU)
        mtu = value
      }

      val addresses =
          params["address"].orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

      return Result.Ok(
          WireGuardUri(secret, host, port, publicKey, reserved, addresses, mtu, name)
      )
    }

    fun isValid(raw: String): Boolean = parse(raw) is Result.Ok

    private fun decode(s: String): String =
        try {
          URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")
        } catch (e: IllegalArgumentException) {
          s
        }

    // WireGuard keys are 32 bytes in standard base64 (44 chars with one '=').
    private fun isKey(s: String): Boolean =
        try {
          Base64.getDecoder().decode(s.trim()).size == 32
        } catch (e: IllegalArgumentException) {
          false
        }

    private fun splitHostPort(endpoint: String): Pair<String, Int>? {
      val host: String
      val portText: String
      if (endpoint.startsWith("[")) { // [v6]:port
        val close = endpoint.indexOf(']')
        if (close < 0 || endpoint.getOrNull(close + 1) != ':') return null
        host = endpoint.substring(1, close)
        portText = endpoint.substring(close + 2)
      } else {
        val colon = endpoint.lastIndexOf(':')
        if (colon <= 0) return null
        host = endpoint.substring(0, colon)
        portText = endpoint.substring(colon + 1)
      }
      val port = portText.toIntOrNull() ?: return null
      if (host.isBlank() || port !in 1..65535) return null
      return host to port
    }
  }
}
