// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestNewWGKeyPair(t *testing.T) {
	kp, err := newWGKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(kp.pub[:]) {
		t.Fatal("public key does not match private key")
	}
	for _, s := range []string{kp.privBase64(), kp.pubBase64()} {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad key encoding %q: %v", s, err)
		}
	}
	kp2, _ := newWGKeyPair()
	if kp.priv == kp2.priv {
		t.Fatal("two generated keys are identical")
	}
}

func TestWireGuardURI(t *testing.T) {
	// A key containing every character class that needs escaping.
	secret := "a+b/cdefghijklmnopqrstuvwxyz0123456789ABCDE="
	pub := "P+u/bcdefghijklmnopqrstuvwxyz0123456789ABCDE="
	got := wireGuardURI("127.0.0.1", 41641, secret, pub,
		[]string{"100.64.1.2/32", "fd7a:115c:a1e0::1/128"}, 1280, "Tailscale")

	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "wireguard" || u.Host != "127.0.0.1:41641" || u.Fragment != "Tailscale" {
		t.Fatalf("unexpected URI %q", got)
	}
	if user := u.User.Username(); user != secret {
		t.Fatalf("secret key = %q, want %q", user, secret)
	}
	q := u.Query()
	if q.Get("publickey") != pub {
		t.Fatalf("publickey = %q, want %q", q.Get("publickey"), pub)
	}
	if q.Get("address") != "100.64.1.2/32,fd7a:115c:a1e0::1/128" || q.Get("mtu") != "1280" {
		t.Fatalf("unexpected query %q", u.RawQuery)
	}
	if strings.ContainsAny(strings.SplitN(strings.TrimPrefix(got, "wireguard://"), "@", 2)[0], "+/=") {
		t.Fatalf("secret key not percent-encoded in %q", got)
	}
}

func TestWGIPCConfig(t *testing.T) {
	ours, _ := newWGKeyPair()
	peer, _ := newWGKeyPair()
	cfg := wgIPCConfig(ours, peer.pub)
	for _, want := range []string{"private_key=", "listen_port=0\n", "replace_peers=true\n", "public_key=", "allowed_ip=0.0.0.0/0\n", "allowed_ip=::/0\n"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, ours.privBase64()) {
		t.Error("IPC config must use hex, not base64")
	}
}

func TestListenPortFromIPC(t *testing.T) {
	p, err := listenPortFromIPC("private_key=00\nlisten_port=43210\nfwmark=0\n")
	if err != nil || p != 43210 {
		t.Fatalf("got %d, %v", p, err)
	}
	if _, err := listenPortFromIPC("private_key=00\n"); err == nil {
		t.Fatal("expected error")
	}
}
