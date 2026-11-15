// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// This file holds the pure (no Tailscale / wireguard-go types) helpers of the
// Magic V2Ray mode: key generation, the wireguard-go IPC config and the
// wireguard:// share link. Keeping them dependency-free makes them unit
// testable (see magicv2ray_uri_test.go).

const (
	// magicEndpointHost is the only address the local WireGuard endpoint is
	// advertised on. Magic V2Ray runs on the same device.
	magicEndpointHost = "127.0.0.1"

	// magicEndpointMTU is the MTU written into the link. It matches
	// Tailscale's own TUN MTU (defaultMTU) so no inner packet is ever larger
	// than what the tailnet carries.
	magicEndpointMTU = defaultMTU

	// magicEndpointName is the #name fragment of the link.
	magicEndpointName = "Tailscale"
)

// wgKeyPair is a Curve25519 WireGuard key pair.
type wgKeyPair struct {
	priv [32]byte
	pub  [32]byte
}

// newWGKeyPair generates a fresh key pair (same clamping as `wg genkey`).
func newWGKeyPair() (wgKeyPair, error) {
	var kp wgKeyPair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		return wgKeyPair{}, fmt.Errorf("generate private key: %w", err)
	}
	kp.priv[0] &= 248
	kp.priv[31] = (kp.priv[31] & 127) | 64
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		return wgKeyPair{}, fmt.Errorf("derive public key: %w", err)
	}
	copy(kp.pub[:], pub)
	return kp, nil
}

// privBase64 / pubBase64 are the standard-base64 forms used in wireguard://
// links and in `wg` config files.
func (k wgKeyPair) privBase64() string { return base64.StdEncoding.EncodeToString(k.priv[:]) }
func (k wgKeyPair) pubBase64() string  { return base64.StdEncoding.EncodeToString(k.pub[:]) }

// wgIPCConfig returns the wireguard-go UAPI configuration for the Tailscale
// side of the local tunnel: our private key, a random loopback listen port
// and exactly one peer (Magic V2Ray) that may send/receive any address. The
// peer's endpoint is learned from its first handshake (roaming).
func wgIPCConfig(ours wgKeyPair, peerPub [32]byte) string {
	var sb strings.Builder
	sb.WriteString("private_key=" + hex.EncodeToString(ours.priv[:]) + "\n")
	sb.WriteString("listen_port=0\n")
	sb.WriteString("replace_peers=true\n")
	sb.WriteString("public_key=" + hex.EncodeToString(peerPub[:]) + "\n")
	sb.WriteString("allowed_ip=0.0.0.0/0\n")
	sb.WriteString("allowed_ip=::/0\n")
	return sb.String()
}

// magicEndpointInfo describes the running local WireGuard endpoint. It is what
// MagicV2RayEndpointInfoJSON returns to Kotlin.
type magicEndpointInfo struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// SecretKey is the private key Magic V2Ray must use (base64). It is the
	// secret of the *client*; it only ever authenticates to this endpoint.
	SecretKey string `json:"secretKey"`
	// PublicKey is the public key of the Tailscale side (base64), i.e. the
	// `publickey=` parameter of the link.
	PublicKey string `json:"publicKey"`
	// Addresses are the node's own tailnet addresses as CIDRs (x/32, x/128).
	Addresses []string `json:"addresses"`
	MTU       int      `json:"mtu"`
	Name      string   `json:"name"`
	// URI is the ready-to-use wireguard:// link.
	URI string `json:"uri"`
}

// wireGuardURI builds the V2Ray-style share link understood by Magic V2Ray:
//
//	wireguard://<secretKey>@<host>:<port>?publickey=<key>&address=<cidr,cidr>&mtu=<n>#<name>
//
// Keys are percent-encoded because base64 contains '+', '/' and '='.
func wireGuardURI(host string, port int, secretKeyB64, publicKeyB64 string, addresses []string, mtu int, name string) string {
	var sb strings.Builder
	sb.WriteString("wireguard://")
	sb.WriteString(url.QueryEscape(secretKeyB64))
	sb.WriteString("@")
	sb.WriteString(host)
	sb.WriteString(":")
	sb.WriteString(strconv.Itoa(port))
	sb.WriteString("?publickey=")
	sb.WriteString(url.QueryEscape(publicKeyB64))
	if len(addresses) > 0 {
		sb.WriteString("&address=")
		sb.WriteString(strings.Join(addresses, ","))
	}
	sb.WriteString("&mtu=")
	sb.WriteString(strconv.Itoa(mtu))
	if name != "" {
		sb.WriteString("#")
		sb.WriteString(url.PathEscape(name))
	}
	return sb.String()
}

// listenPortFromIPC extracts listen_port from a wireguard-go IpcGet dump.
func listenPortFromIPC(dump string) (int, error) {
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "listen_port="); ok {
			p, err := strconv.Atoi(v)
			if err != nil || p <= 0 || p > 65535 {
				return 0, fmt.Errorf("bad listen_port %q", v)
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("listen_port not found in IPC dump")
}
