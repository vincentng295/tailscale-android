// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"sync"

	"github.com/tailscale/wireguard-go/conn"
)

// learnBind wraps the stock UDP bind of the local Magic V2Ray WireGuard
// endpoint for two reasons.
//
// Roaming: Tailscale's wireguard-go fork never learns a peer's endpoint from
// the packets it receives (magicsock supplies endpoints in the normal Tailscale
// case). Without an endpoint, the answer to Magic V2Ray's handshake fails with
// "no known endpoint for peer" and the tunnel never comes up. So the first
// authenticated-looking source address is handed to onSource, which sets it as
// the peer's endpoint.
//
// Exposure: the stock bind listens on the wildcard address and is therefore
// reachable from the LAN. Magic V2Ray runs on this device and always talks
// from loopback, so datagrams from any other source are dropped here.
type learnBind struct {
	conn.Bind

	// onSource is called (on its own goroutine) with each new loopback
	// source address, e.g. "127.0.0.1:49948". It must be safe to call after the
	// device was closed.
	onSource func(addr string)

	mu   sync.Mutex
	last string
}

func newLearnBind(inner conn.Bind, onSource func(addr string)) *learnBind {
	return &learnBind{Bind: inner, onSource: onSource}
}

// Open implements conn.Bind.
func (b *learnBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = b.wrap(fn)
	}
	return out, actual, nil
}

func (b *learnBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		n, err := fn(slab, packets)
		if n <= 0 {
			return n, err
		}
		kept := 0
		for i := 0; i < n; i++ {
			p := packets[i]
			if p.Endpoint == nil || !p.Endpoint.DstIP().IsLoopback() {
				continue // not from this device: drop
			}
			packets[kept] = p
			kept++
		}
		if kept > 0 {
			b.learn(packets[kept-1].Endpoint.DstToString())
		}
		return kept, err
	}
}

// learn reports addr to onSource when it differs from the last one seen.
func (b *learnBind) learn(addr string) {
	b.mu.Lock()
	changed := addr != b.last
	b.last = addr
	b.mu.Unlock()
	if changed && b.onSource != nil {
		// Never call back into the device from its own receive goroutine: closing
		// the device waits for that goroutine, so a synchronous IpcSet could
		// deadlock against Close.
		go b.onSource(addr)
	}
}
