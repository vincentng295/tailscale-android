// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/netns"
)

// Magic V2Ray mode: instead of an Android VpnService, Tailscale exposes a
// WireGuard server on 127.0.0.1 and Magic V2Ray's VPN carries the tailnet
// traffic into it.
//
//	apps -> Magic V2Ray VPN -> xray wireguard outbound
//	      -> UDP 127.0.0.1:<port> -> [wireguard-go device]   (this file)
//	      -> in-memory packet bridge -> multiTUN -> Tailscale engine -> tailnet
//
// The engine is unchanged: it still reads/writes plain IP packets from a
// tun.Device (the multiTUN), only that device is no longer a VpnService fd but
// the engine end of an in-memory pair. The wireguard-go device owns the other
// end and does the WireGuard encryption towards Magic V2Ray. All keys are
// generated per start and live only in memory.

// magicEndpoint is the running local WireGuard endpoint.
type magicEndpoint struct {
	dev      *device.Device
	chEngine *tuntest.ChannelTUN // end handed to the Tailscale engine (via multiTUN)
	chWG     *tuntest.ChannelTUN // end owned by the wireguard-go device
	done     chan struct{}
	pumps    sync.WaitGroup
	info     magicEndpointInfo
	infoJSON string
}

// StartMagicV2RayEndpoint starts (or returns the already running) local
// WireGuard endpoint and returns the wireguard:// link to hand to Magic V2Ray.
//
// Tailscale must already be logged in and have its tailnet addresses (state
// Starting/Running), otherwise an error is returned. Any active VpnService
// device is dropped: Magic V2Ray mode and VpnService mode are exclusive, the
// caller must not (re)start IPNService while this endpoint runs.
func (a *App) StartMagicV2RayEndpoint() (string, error) {
	a.ready.Wait()
	a.magicMu.Lock()
	defer a.magicMu.Unlock()

	addrs, err := a.selfCIDRs()
	if err != nil {
		return "", err
	}
	if a.magic != nil {
		if slices.Equal(a.magic.info.Addresses, addrs) {
			return a.magic.info.URI, nil
		}
		// Our tailnet addresses changed: the link is stale, rebuild.
		a.stopMagicLocked()
	}
	ep, err := a.newMagicEndpoint(addrs)
	if err != nil {
		return "", err
	}
	a.magic = ep
	log.Printf("magicv2ray: endpoint %s:%d up, addresses %v", ep.info.Host, ep.info.Port, ep.info.Addresses)
	return ep.info.URI, nil
}

// StopMagicV2RayEndpoint tears the endpoint down. Safe to call when it is not
// running.
func (a *App) StopMagicV2RayEndpoint() {
	a.ready.Wait()
	a.magicMu.Lock()
	defer a.magicMu.Unlock()
	a.stopMagicLocked()
}

// MagicV2RayEndpointInfoJSON returns the endpoint description as JSON
// (host, port, secretKey, publicKey, addresses, mtu, name, uri), or an empty
// string when the endpoint is not running.
func (a *App) MagicV2RayEndpointInfoJSON() string {
	a.magicMu.Lock()
	defer a.magicMu.Unlock()
	if a.magic == nil {
		return ""
	}
	return a.magic.infoJSON
}

// selfCIDRs returns this node's tailnet addresses as /32 and /128 CIDRs.
func (a *App) selfCIDRs() ([]string, error) {
	st := a.backend.Status()
	if st == nil || len(st.TailscaleIPs) == 0 {
		return nil, errors.New("Tailscale has no tailnet address yet (not logged in or not running)")
	}
	var out []string
	for _, ip := range st.TailscaleIPs {
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	return out, nil
}

func (a *App) newMagicEndpoint(addrs []string) (_ *magicEndpoint, err error) {
	b := a.tunBackend
	if b == nil {
		return nil, errors.New("backend not ready")
	}
	ours, err := newWGKeyPair()
	if err != nil {
		return nil, err
	}
	magic, err := newWGKeyPair() // the identity Magic V2Ray will use
	if err != nil {
		return nil, err
	}

	ep := &magicEndpoint{
		chEngine: tuntest.NewChannelTUN(),
		chWG:     tuntest.NewChannelTUN(),
		done:     make(chan struct{}),
	}

	// conn.NewDefaultBind listens on the wildcard address, so it is wrapped below to
	// accept loopback senders only.
	// The stock bind is wrapped: it drops non-loopback senders and tells us
	// Magic V2Ray's source address, which becomes the peer's endpoint (the fork
	// does not learn endpoints by itself, see learnBind). Magic V2Ray retries the
	// handshake every few seconds, so if the very first answer races the
	// endpoint update, the next attempt completes it.
	bind := newLearnBind(conn.NewDefaultBind(), func(addr string) {
		if err := ep.dev.IpcSet(wgEndpointIPC(magic.pub, addr)); err != nil {
			log.Printf("magicv2ray: set peer endpoint %s: %v", addr, err)
			return
		}
		log.Printf("magicv2ray: peer endpoint %s", addr)
	})
	ep.dev = device.NewDevice(ep.chWG.TUN(), bind, device.NewLogger(device.LogLevelError, "magicv2ray-wg: "))
	defer func() {
		if err != nil {
			ep.dev.Close()
		}
	}()
	if err := ep.dev.IpcSet(wgIPCConfig(ours, magic.pub)); err != nil {
		return nil, fmt.Errorf("configure wireguard device: %w", err)
	}
	if err := ep.dev.Up(); err != nil {
		return nil, fmt.Errorf("bring wireguard device up: %w", err)
	}
	dump, err := ep.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("read wireguard device state: %w", err)
	}
	port, err := listenPortFromIPC(dump)
	if err != nil {
		return nil, err
	}

	ep.info = magicEndpointInfo{
		Host:      magicEndpointHost,
		Port:      port,
		SecretKey: magic.privBase64(),
		PublicKey: ours.pubBase64(),
		Addresses: addrs,
		MTU:       magicEndpointMTU,
		Name:      magicEndpointName,
	}
	ep.info.URI = wireGuardURI(ep.info.Host, ep.info.Port, ep.info.SecretKey, ep.info.PublicKey, ep.info.Addresses, ep.info.MTU, ep.info.Name)
	j, err := json.Marshal(ep.info)
	if err != nil {
		return nil, err
	}
	ep.infoJSON = string(j)

	// Bridge the two in-memory TUNs:
	//   engine wrote a packet  -> wireguard-go reads it, encrypts, sends to Magic
	//   Magic sent a packet    -> wireguard-go decrypts and writes it -> engine reads it
	ep.pumps.Add(2)
	go pumpPackets(ep.chEngine.Outbound, ep.chWG.Inbound, ep.done, &ep.pumps)
	go pumpPackets(ep.chWG.Outbound, ep.chEngine.Inbound, ep.done, &ep.pumps)

	// Replace any VpnService device with the engine end of the bridge.
	b.CloseTUNs()
	b.devices.add(ep.chEngine.TUN())
	if b.devices.Up() {
		log.Printf("magicv2ray: tunnel brought up")
	}

	// There is no VpnService, so nothing Tailscale opens is captured by a VPN
	// of ours; but Magic V2Ray's VPN is the default route. Bind Tailscale's own
	// sockets (control, DERP, magicsock) to the underlying network so they do
	// not run through Magic V2Ray.
	netns.SetAndroidBindToNetworkFunc(func(fd int) error {
		if ok := a.appCtx.BindSocketToNetwork(int32(fd)); !ok {
			log.Printf("[unexpected] IPNService.bindSocketToNetwork(%d) returned false", fd)
		}
		return nil
	})
	a.backend.DebugRebind()
	return ep, nil
}

func (a *App) stopMagicLocked() {
	ep := a.magic
	if ep == nil {
		return
	}
	a.magic = nil
	b := a.tunBackend

	// Stop the bridge before anything is closed: the TUNs close their Inbound
	// channels, and a pump sending on a closed channel would panic.
	close(ep.done)
	ep.pumps.Wait()

	if b.devices.Down() {
		log.Printf("magicv2ray: tunnel brought down")
	}
	b.CloseTUNs() // closes the engine end
	ep.dev.Close() // closes the wireguard-go end and its UDP socket
	netns.SetAndroidBindToNetworkFunc(nil)
	log.Printf("magicv2ray: endpoint stopped")
}

// pumpPackets copies packets from src to dst until done is closed or src is
// closed. The ChannelTUN Write implementation already copies the packet, so
// the buffers received here are owned by us.
func pumpPackets(src <-chan []byte, dst chan<- []byte, done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-done:
			return
		case pkt, ok := <-src:
			if !ok {
				return
			}
			select {
			case dst <- pkt:
			case <-done:
				return
			}
		}
	}
}
