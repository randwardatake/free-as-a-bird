package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/randwardatake/free-as-a-bird/internal/board"
)

// A member reached only through a relay must not stall blob downloads:
// streams over a relayed connection wait for hole punching, which never
// succeeds here, so such peers must be skipped as data sources.
func TestRelayedMemberDoesNotStallFetch(t *testing.T) {
	tn := newTestNet(t)
	hub := tn.startWith("hub", func(c *Config) { c.Hub = true })
	a, b, c := tn.start("A"), tn.start("B"), tn.start("C")

	// B holds a reservation on the hub; A reaches B only via the circuit.
	link(t, b, hub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hubInfo := peer.AddrInfo{ID: hub.host.ID(), Addrs: hub.host.Addrs()}
	if _, err := client.Reserve(ctx, b.host, hubInfo); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	circuit, err := ma.NewMultiaddr(hub.Addrs()[0] + "/p2p-circuit/p2p/" + b.host.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.host.Connect(ctx, peer.AddrInfo{ID: b.host.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatalf("connect via relay: %v", err)
	}
	eventually(t, "A identifies B as a member", func() bool { return a.isMember(b.host.ID()) })
	if a.direct(b.host.ID()) {
		t.Skip("hole punching produced a direct connection; nothing to test")
	}

	// B and C hold a post and its image; A has the post but not the image.
	// Nothing is gossiped, so only fetchOne can bring the image to A.
	link(t, a, c)
	im := testImage(t)
	cid, _ := b.Blobs.Put(im.Data)
	c.Blobs.Put(im.Data)
	p := &board.Post{Board: "linux", Body: "relayed", Time: time.Now().Unix(),
		Image: &board.ImageRef{CID: cid, ThumbCID: cid, Mime: im.Mime, Width: im.Width, Height: im.Height, Size: int64(len(im.Data))}}
	if err := p.Seal(tn.mod, nil, tn.gen.Payload.Limits.PoWBits); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, b, c} {
		if _, err := n.Store.Add(p, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	start := time.Now()
	ok := a.fetchOne(fetchReq{cid: cid, hint: b.host.ID()})
	if took := time.Since(start); !ok || took > 5*time.Second {
		t.Fatalf("fetch via direct peer: ok=%v after %v (stalled on the relayed peer?)", ok, took)
	}
}
