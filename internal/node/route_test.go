package node

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/randwardatake/p2psite/internal/route"
)

// A visitor builds a two-relay circuit (visitor -> R1 -> R2) and exchanges
// data with the exit hop, R2, which here echoes. Both relay hops onion-peel
// real cells over real libp2p streams.
func TestCircuitTwoRelays(t *testing.T) {
	tn := newTestNet(t)
	visitor := tn.start("visitor")
	r1 := tn.start("r1")
	r2 := tn.start("r2")

	// The visitor dials R1; R1 must be able to dial R2 to extend.
	link(t, visitor, r1)
	link(t, r1, r2)

	hops := []Hop{
		{ID: r1.Host().ID(), Route: r1.RouteKey()},
		{ID: r2.Host().ID(), Route: r2.RouteKey()},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := visitor.BuildCircuit(ctx, hops)
	if err != nil {
		t.Fatalf("build circuit: %v", err)
	}
	defer c.Close()

	// Several round trips, to exercise the per-hop nonce counters in lockstep.
	for i := 0; i < 3; i++ {
		msg := []byte("hello through two relays " + strings.Repeat("!", i))
		reply, err := c.Send(msg)
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if !bytes.Equal(reply, msg) {
			t.Fatalf("send %d: reply %q != %q", i, reply, msg)
		}
	}
}

// With a custom exit handler the last hop transforms the payload, proving the
// exit sees the real plaintext and nothing in between does.
func TestCircuitExitHandler(t *testing.T) {
	tn := newTestNet(t)
	visitor := tn.start("visitor")
	r1 := tn.start("r1")
	r2 := tn.start("r2")
	r2.RouteHandler = func(b []byte) []byte { return append([]byte("echo:"), b...) }

	link(t, visitor, r1)
	link(t, r1, r2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := visitor.BuildCircuit(ctx, []Hop{
		{ID: r1.Host().ID(), Route: r1.RouteKey()},
		{ID: r2.Host().ID(), Route: r2.RouteKey()},
	})
	if err != nil {
		t.Fatalf("build circuit: %v", err)
	}
	defer c.Close()

	reply, err := c.Send([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "echo:ping" {
		t.Fatalf("reply %q", reply)
	}
}

// A single-hop circuit still works: the first hop is also the exit.
func TestCircuitSingleHop(t *testing.T) {
	tn := newTestNet(t)
	visitor := tn.start("visitor")
	r1 := tn.start("r1")
	link(t, visitor, r1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := visitor.BuildCircuit(ctx, []Hop{{ID: r1.Host().ID(), Route: r1.RouteKey()}})
	if err != nil {
		t.Fatalf("build circuit: %v", err)
	}
	defer c.Close()

	reply, err := c.Send([]byte("solo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "solo" {
		t.Fatalf("reply %q", reply)
	}
}

// Rendezvous: a visitor and a land each build their own circuit to a common
// rendezvous relay R, which splices them. Neither R nor any hop sees both
// endpoints: the visitor reaches R through m1, the land through m2.
//
//	visitor -> m1 -> R  (establish, cookie)
//	land    -> m2 -> R  (join, same cookie)
func TestRendezvousSplice(t *testing.T) {
	tn := newTestNet(t)
	visitor := tn.start("visitor")
	m1 := tn.start("m1")
	r := tn.start("R")
	m2 := tn.start("m2")
	land := tn.start("land")

	link(t, visitor, m1)
	link(t, m1, r)
	link(t, land, m2)
	link(t, m2, r)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vc, err := visitor.BuildCircuit(ctx, []Hop{
		{ID: m1.Host().ID(), Route: m1.RouteKey()},
		{ID: r.Host().ID(), Route: r.RouteKey()},
	})
	if err != nil {
		t.Fatalf("visitor circuit: %v", err)
	}
	defer vc.Close()

	cookie := []byte("one-time-rendezvous-cookie-0001")
	if err := vc.EstablishRendezvous(cookie); err != nil {
		t.Fatalf("establish: %v", err)
	}

	lc, err := land.BuildCircuit(ctx, []Hop{
		{ID: m2.Host().ID(), Route: m2.RouteKey()},
		{ID: r.Host().ID(), Route: r.RouteKey()},
	})
	if err != nil {
		t.Fatalf("land circuit: %v", err)
	}
	defer lc.Close()

	if err := lc.JoinRendezvous(cookie); err != nil {
		t.Fatalf("join: %v", err)
	}

	// Land -> visitor, then visitor -> land, a few times each way.
	for i := 0; i < 3; i++ {
		toV := []byte{'L', byte('0' + i)}
		if err := lc.SendRv(toV); err != nil {
			t.Fatalf("land send %d: %v", i, err)
		}
		got, err := vc.RecvRv()
		if err != nil {
			t.Fatalf("visitor recv %d: %v", i, err)
		}
		if !bytes.Equal(got, toV) {
			t.Fatalf("visitor got %q want %q", got, toV)
		}

		toL := []byte{'V', byte('0' + i)}
		if err := vc.SendRv(toL); err != nil {
			t.Fatalf("visitor send %d: %v", i, err)
		}
		got, err = lc.RecvRv()
		if err != nil {
			t.Fatalf("land recv %d: %v", i, err)
		}
		if !bytes.Equal(got, toL) {
			t.Fatalf("land got %q want %q", got, toL)
		}
	}
}

// Joining an unknown cookie fails rather than hanging or splicing wrongly.
func TestRendezvousUnknownCookie(t *testing.T) {
	tn := newTestNet(t)
	land := tn.start("land")
	r := tn.start("R")
	link(t, land, r)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lc, err := land.BuildCircuit(ctx, []Hop{{ID: r.Host().ID(), Route: r.RouteKey()}})
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	if err := lc.JoinRendezvous([]byte("no-such-cookie")); err == nil {
		t.Fatal("join of unknown cookie should fail")
	}
}

// Full hidden-service path: a land registers at an introduction point I, a
// visitor parks a rendezvous at R, then introduces itself through I carrying a
// sealed (R, cookie). The intro point forwards it without reading it; the land
// opens it, joins the rendezvous, and the two exchange end to end. I never
// learns R or the cookie; R never learns the land.
func TestIntroductionFullPath(t *testing.T) {
	tn := newTestNet(t)
	visitor := tn.start("visitor")
	land := tn.start("land")
	intro := tn.start("I")
	rv := tn.start("R")

	// Everyone who must dial each other in this flow.
	link(t, land, intro)
	link(t, land, rv)
	link(t, visitor, rv)
	link(t, visitor, intro)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Land: register at the introduction point and listen.
	landIntroKey := land.RouteKey().Bytes()
	landIntroCirc, err := land.BuildCircuit(ctx, []Hop{{ID: intro.Host().ID(), Route: intro.RouteKey()}})
	if err != nil {
		t.Fatalf("land intro circuit: %v", err)
	}
	defer landIntroCirc.Close()
	if err := landIntroCirc.EstablishIntro(landIntroKey); err != nil {
		t.Fatalf("establish intro: %v", err)
	}

	// Visitor: park a rendezvous at R under a fresh cookie.
	cookie := []byte("rv-cookie-xyzzy-0001")
	visRvCirc, err := visitor.BuildCircuit(ctx, []Hop{{ID: rv.Host().ID(), Route: rv.RouteKey()}})
	if err != nil {
		t.Fatalf("visitor rv circuit: %v", err)
	}
	defer visRvCirc.Close()
	if err := visRvCirc.EstablishRendezvous(cookie); err != nil {
		t.Fatalf("establish rendezvous: %v", err)
	}

	// Visitor: seal (R, cookie) to the land and introduce through I.
	sealed, err := route.SealTo(land.RouteKey(), marshalIntro(Introduction{
		Rendezvous: rv.Host().ID(),
		RvRoute:    rv.RouteKey(),
		Cookie:     cookie,
	}))
	if err != nil {
		t.Fatal(err)
	}

	// The land handles the introduction concurrently: receive, open, join.
	joined := make(chan *Circuit, 1)
	joinErr := make(chan error, 1)
	go func() {
		box, err := landIntroCirc.RecvIntroduce()
		if err != nil {
			joinErr <- err
			return
		}
		pt, err := route.OpenSealed(land.routeKey, box)
		if err != nil {
			joinErr <- err
			return
		}
		in, err := parseIntro(pt)
		if err != nil {
			joinErr <- err
			return
		}
		lc, err := land.BuildCircuit(ctx, []Hop{{ID: in.Rendezvous, Route: in.RvRoute}})
		if err != nil {
			joinErr <- err
			return
		}
		if err := lc.JoinRendezvous(in.Cookie); err != nil {
			joinErr <- err
			return
		}
		joined <- lc
	}()

	visIntroCirc, err := visitor.BuildCircuit(ctx, []Hop{{ID: intro.Host().ID(), Route: intro.RouteKey()}})
	if err != nil {
		t.Fatalf("visitor intro circuit: %v", err)
	}
	defer visIntroCirc.Close()
	if err := visIntroCirc.Introduce(landIntroKey, sealed); err != nil {
		t.Fatalf("introduce: %v", err)
	}

	var landRvCirc *Circuit
	select {
	case landRvCirc = <-joined:
	case err := <-joinErr:
		t.Fatalf("land join: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for land to join rendezvous")
	}
	defer landRvCirc.Close()

	// End-to-end exchange across the rendezvous.
	if err := visRvCirc.SendRv([]byte("hello land")); err != nil {
		t.Fatal(err)
	}
	got, err := landRvCirc.RecvRv()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello land" {
		t.Fatalf("land got %q", got)
	}
	if err := landRvCirc.SendRv([]byte("hello visitor")); err != nil {
		t.Fatal(err)
	}
	got, err = visRvCirc.RecvRv()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello visitor" {
		t.Fatalf("visitor got %q", got)
	}
}
