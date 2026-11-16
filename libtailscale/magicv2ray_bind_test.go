// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
)

type fakeEndpoint struct{ dst netip.AddrPort }

func (e *fakeEndpoint) ClearSrc()           {}
func (e *fakeEndpoint) SrcToString() string { return "" }
func (e *fakeEndpoint) DstToString() string { return e.dst.String() }
func (e *fakeEndpoint) DstToBytes() []byte  { return nil }
func (e *fakeEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func TestLearnBindDropsNonLoopbackAndLearnsSource(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	b := newLearnBind(nil, func(addr string) {
		mu.Lock()
		seen = append(seen, addr)
		mu.Unlock()
	})
	in := []conn.ReceivedPacket{
		{Size: 1, Endpoint: &fakeEndpoint{netip.MustParseAddrPort("192.168.0.9:1111")}},
		{Size: 2, Endpoint: &fakeEndpoint{netip.MustParseAddrPort("127.0.0.1:49948")}},
	}
	fn := b.wrap(func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		copy(packets, in)
		return len(in), nil
	})
	out := make([]conn.ReceivedPacket, 2)
	n, err := fn(nil, out)
	if err != nil || n != 1 || out[0].Size != 2 {
		t.Fatalf("n=%d err=%v out[0]=%+v, want the single loopback packet", n, err, out[0])
	}
	// The same source again must not trigger a second callback.
	if n, _ := fn(nil, out); n != 1 {
		t.Fatalf("second n=%d, want 1", n)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "127.0.0.1:49948" {
		t.Fatalf("seen = %v, want exactly [127.0.0.1:49948]", seen)
	}
}
