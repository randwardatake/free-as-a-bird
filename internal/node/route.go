package node

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/p2psite/internal/route"
)

// This file drives internal/route over libp2p streams: the relay side
// (handleRoute) and the client side that builds a circuit one hop at a time
// (BuildCircuit). See docs/ROUTING.md.
//
// One libp2p stream carries one circuit per hop. Every frame on the wire is
// exactly route.CellSize bytes, so a relay cannot tell cells apart by length.
//
// Inside each onion layer the plaintext starts with a tag byte: a cell is
// either forwarded to the next hop or terminated at this one. A terminated
// cell then carries a relay command. The AEAD tag on each layer authenticates
// it, so a relay that peels its layer knows the cell was built for it.

const (
	tagForward   byte = 0 // the rest is the inner cell for the next hop
	tagTerminate byte = 1 // the rest is a relay command for this hop

	cmdExtend         byte = 1 // extend the circuit to a named peer
	cmdData           byte = 2 // payload for the exit hop
	cmdRendezvous     byte = 3 // register a rendezvous cookie at the exit hop
	cmdRendezvousJoin byte = 4 // join a waiting rendezvous by cookie
	cmdIntroEstablish byte = 5 // a land registers at this hop as an intro point
	cmdIntroduce      byte = 6 // a visitor asks this intro point to reach a land

	mkExtended      byte = 1 // backward: a CREATED from the newly added hop
	mkData          byte = 2 // backward: a reply, or a cell from the spliced peer
	mkRvEstablished byte = 3 // backward: this circuit is parked as a rendezvous
	mkRvJoined      byte = 4 // backward: the two half-circuits are now spliced
	mkRvFailed      byte = 5 // backward: no circuit is waiting on that cookie
	mkIntroReady    byte = 6 // backward: this circuit is registered as an intro point
	mkIntroAck      byte = 7 // backward: the INTRODUCE was delivered to the land
	mkIntroduce     byte = 8 // backward: a forwarded INTRODUCE payload for the land
)

// rendezPoint links the two half-circuits that meet at a rendezvous relay.
// Each side's sendBack writes a backward data cell towards that side's client,
// so the relay forwards between them without ever learning either endpoint.
type rendezPoint struct {
	mu   sync.Mutex
	a, b func([]byte) error
}

func (r *rendezPoint) peer(side byte) func([]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if side == 'a' {
		return r.b
	}
	return r.a
}

var errShort = errors.New("route: short payload")

// cellConn reads and writes fixed-size cells on one stream. Writes are
// serialised; reads come from a single goroutine per direction.
type cellConn struct {
	s   network.Stream
	r   *bufio.Reader
	wmu sync.Mutex
}

func newCellConn(s network.Stream) *cellConn {
	return &cellConn{s: s, r: bufio.NewReaderSize(s, 2*route.CellSize)}
}

func (c *cellConn) read() (route.Cell, error) {
	buf := make([]byte, route.CellSize)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return route.Cell{}, err
	}
	return route.ParseCell(buf)
}

func (c *cellConn) write(cell route.Cell) error {
	b, err := cell.Marshal()
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.s.Write(b)
	return err
}

// handleRoute is the relay side of the route protocol.
func (n *Node) handleRoute(s network.Stream) {
	defer s.Close()
	cc := newCellConn(s)

	first, err := cc.read()
	if err != nil || first.Cmd != route.CmdCreate {
		return
	}
	created, keys, err := route.ServerHandshake([]byte(n.host.ID()), n.routeKey, first.Body)
	if err != nil {
		n.log.Debug("route handshake failed", "err", err)
		return
	}
	if err := cc.write(route.Cell{Cmd: route.CmdCreated, Circ: first.Circ, Body: created}); err != nil {
		return
	}
	fwd, err := route.NewLayer(keys.Fwd[:])
	if err != nil {
		return
	}
	bwd, err := route.NewLayer(keys.Bwd[:])
	if err != nil {
		return
	}

	var next *cellConn
	// Rendezvous state, set if this hop becomes a rendezvous for its circuit.
	var rp *rendezPoint
	var side byte
	var rvCookie string
	// Intro state, set if a land registers here as an introduction point.
	var introKey string
	defer func() {
		if next != nil {
			next.s.Close()
		}
		if rp != nil && side == 'a' {
			n.rendez.Delete(rvCookie) // drop a cookie that was never joined
		}
		if introKey != "" {
			n.intro.Delete(introKey)
		}
	}()

	sendMarker := func(marker byte, p []byte) error {
		return cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal(append([]byte{marker}, p...))})
	}
	sendBack := func(p []byte) error { return sendMarker(mkData, p) }

	for {
		cell, err := cc.read()
		if err != nil {
			return
		}
		if cell.Cmd == route.CmdDestroy {
			return
		}
		if cell.Cmd != route.CmdRelay {
			return
		}
		inner, err := fwd.Open(cell.Body)
		if err != nil {
			n.log.Debug("route peel failed", "err", err)
			return
		}
		if len(inner) < 1 {
			return
		}
		tag, rest := inner[0], inner[1:]

		if tag == tagForward {
			if next == nil {
				return
			}
			if err := next.write(route.Cell{Cmd: route.CmdRelay, Body: rest}); err != nil {
				return
			}
			continue
		}

		// tagTerminate: a relay command for this hop.
		if len(rest) < 1 {
			return
		}
		switch cmd, payload := rest[0], rest[1:]; cmd {
		case cmdExtend:
			if next != nil {
				return // a circuit extends once at each hop
			}
			pid, create2, err := parseExtend(payload)
			if err != nil {
				return
			}
			ns, err := n.host.NewStream(n.ctx, pid, n.proto("route"))
			if err != nil {
				n.log.Debug("route extend dial failed", "peer", pid, "err", err)
				return
			}
			next = newCellConn(ns)
			if err := next.write(route.Cell{Cmd: route.CmdCreate, Body: create2}); err != nil {
				return
			}
			cr, err := next.read()
			if err != nil || cr.Cmd != route.CmdCreated {
				return
			}
			back := bwd.Seal(append([]byte{mkExtended}, cr.Body...))
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: back}); err != nil {
				return
			}
			go n.routeBackwardPump(next, cc, bwd)
		case cmdData:
			if rp != nil {
				// Spliced: hand the payload to the other half-circuit.
				if peer := rp.peer(side); peer != nil {
					_ = peer(payload)
				}
				continue
			}
			back := bwd.Seal(append([]byte{mkData}, n.exitData(payload)...))
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: back}); err != nil {
				return
			}
		case cmdRendezvous:
			if rp != nil {
				return
			}
			rp = &rendezPoint{a: sendBack}
			side = 'a'
			rvCookie = string(payload)
			if _, loaded := n.rendez.LoadOrStore(rvCookie, rp); loaded {
				rp = nil // cookie already in use
				if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvFailed})}); err != nil {
					return
				}
				continue
			}
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvEstablished})}); err != nil {
				return
			}
		case cmdRendezvousJoin:
			if rp != nil {
				return
			}
			v, ok := n.rendez.LoadAndDelete(string(payload))
			if !ok {
				if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvFailed})}); err != nil {
					return
				}
				continue
			}
			rp = v.(*rendezPoint)
			side = 'b'
			rp.mu.Lock()
			rp.b = sendBack
			rp.mu.Unlock()
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvJoined})}); err != nil {
				return
			}
		case cmdIntroEstablish:
			if introKey != "" {
				return
			}
			introKey = string(payload) // the land's route public key
			deliver := func(sealed []byte) error { return sendMarker(mkIntroduce, sealed) }
			if _, loaded := n.intro.LoadOrStore(introKey, deliver); loaded {
				introKey = ""
				if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvFailed})}); err != nil {
					return
				}
				continue
			}
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkIntroReady})}); err != nil {
				return
			}
		case cmdIntroduce:
			key, sealed, err := parseIntroduce(payload)
			if err != nil {
				return
			}
			v, ok := n.intro.Load(string(key))
			if !ok {
				if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvFailed})}); err != nil {
					return
				}
				continue
			}
			if err := v.(func([]byte) error)(sealed); err != nil {
				// The land's circuit is gone; forget it.
				n.intro.Delete(string(key))
				if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkRvFailed})}); err != nil {
					return
				}
				continue
			}
			if err := cc.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal([]byte{mkIntroAck})}); err != nil {
				return
			}
		default:
			return
		}
	}
}

// routeBackwardPump forwards cells coming from a later hop back towards the
// client, adding this hop's backward layer to each.
func (n *Node) routeBackwardPump(from, to *cellConn, bwd *route.Layer) {
	for {
		cell, err := from.read()
		if err != nil || cell.Cmd != route.CmdRelay {
			return
		}
		if err := to.write(route.Cell{Cmd: route.CmdRelay, Body: bwd.Seal(cell.Body)}); err != nil {
			return
		}
	}
}

// exitData handles a data cell at the exit hop. The default echoes the
// payload; lands set RouteHandler to proxy to their local service.
func (n *Node) exitData(payload []byte) []byte {
	if n.RouteHandler != nil {
		return n.RouteHandler(payload)
	}
	return payload
}

func buildExtend(pid peer.ID, create []byte) []byte {
	idb := []byte(pid)
	out := make([]byte, 0, 1+2+len(idb)+len(create))
	out = append(out, cmdExtend)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(idb)))
	out = append(out, l[:]...)
	out = append(out, idb...)
	out = append(out, create...)
	return out
}

// parseExtend reads the body after the cmdExtend byte: a length-prefixed peer
// id and the 32-byte CREATE payload.
func parseExtend(b []byte) (peer.ID, []byte, error) {
	if len(b) < 2 {
		return "", nil, errShort
	}
	l := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) != l+32 {
		return "", nil, errShort
	}
	return peer.ID(b[:l]), b[l : l+32], nil
}

// buildIntroduce frames a cmdIntroduce payload: the land's introduction key
// (its route public key) and the sealed INTRODUCE box the intro point relays
// on without reading.
func buildIntroduce(introKey, sealed []byte) []byte {
	out := make([]byte, 0, 2+len(introKey)+len(sealed))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(introKey)))
	out = append(out, l[:]...)
	out = append(out, introKey...)
	out = append(out, sealed...)
	return out
}

func parseIntroduce(b []byte) (key, sealed []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errShort
	}
	l := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < l {
		return nil, nil, errShort
	}
	return b[:l], b[l:], nil
}

// Introduction is what a visitor seals to a land: where to meet (the
// rendezvous relay) and the one-time cookie to present there.
type Introduction struct {
	Rendezvous peer.ID
	RvRoute    *ecdh.PublicKey
	Cookie     []byte
}

func marshalIntro(in Introduction) []byte {
	idb := []byte(in.Rendezvous)
	rv := in.RvRoute.Bytes()
	out := make([]byte, 0, 2+len(idb)+len(rv)+len(in.Cookie))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(idb)))
	out = append(out, l[:]...)
	out = append(out, idb...)
	out = append(out, rv...)
	out = append(out, in.Cookie...)
	return out
}

func parseIntro(b []byte) (Introduction, error) {
	var in Introduction
	if len(b) < 2 {
		return in, errShort
	}
	l := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < l+32 {
		return in, errShort
	}
	in.Rendezvous = peer.ID(b[:l])
	rv, err := ecdh.X25519().NewPublicKey(b[l : l+32])
	if err != nil {
		return in, err
	}
	in.RvRoute = rv
	in.Cookie = append([]byte(nil), b[l+32:]...)
	return in, nil
}

// Hop names one relay on a circuit: its peer id and its static route key.
type Hop struct {
	ID    peer.ID
	Route *ecdh.PublicKey
}

// Circuit is a client's view of a built circuit.
type Circuit struct {
	conn *cellConn
	fwd  []*route.Layer // per hop: seals a cell towards that hop
	bwd  []*route.Layer // per hop: opens a cell coming back from it
}

// RouteKey returns this node's static route public key, so a peer can be
// named as a Hop.
func (n *Node) RouteKey() *ecdh.PublicKey { return n.routeKey.PublicKey() }

// BuildCircuit opens a circuit through hops in order, handshaking with the
// first directly and telescoping to each later hop through the ones before it.
func (n *Node) BuildCircuit(ctx context.Context, hops []Hop) (*Circuit, error) {
	if len(hops) == 0 {
		return nil, errors.New("route: no hops")
	}
	s, err := n.host.NewStream(ctx, hops[0].ID, n.proto("route"))
	if err != nil {
		return nil, err
	}
	c := &Circuit{conn: newCellConn(s)}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	// First hop: a direct CREATE/CREATED on the stream.
	cs, create, err := route.CreateClient([]byte(hops[0].ID), hops[0].Route)
	if err != nil {
		return nil, err
	}
	if err := c.conn.write(route.Cell{Cmd: route.CmdCreate, Body: create}); err != nil {
		return nil, err
	}
	cr, err := c.conn.read()
	if err != nil {
		return nil, err
	}
	if cr.Cmd != route.CmdCreated {
		return nil, errors.New("route: expected CREATED")
	}
	keys, err := cs.Finish(cr.Body)
	if err != nil {
		return nil, err
	}
	if err := c.addHop(keys); err != nil {
		return nil, err
	}

	// Later hops: EXTEND through the hops already built.
	for i := 1; i < len(hops); i++ {
		cs, create, err := route.CreateClient([]byte(hops[i].ID), hops[i].Route)
		if err != nil {
			return nil, err
		}
		body := c.sealToHop(i-1, buildExtend(hops[i].ID, create))
		if err := c.conn.write(route.Cell{Cmd: route.CmdRelay, Body: body}); err != nil {
			return nil, err
		}
		resp, err := c.conn.read()
		if err != nil {
			return nil, err
		}
		if resp.Cmd != route.CmdRelay {
			return nil, errors.New("route: expected relay cell")
		}
		inner, err := c.openFromHop(i-1, resp.Body)
		if err != nil {
			return nil, err
		}
		if len(inner) < 1 || inner[0] != mkExtended {
			return nil, errors.New("route: expected extended")
		}
		keys, err := cs.Finish(inner[1:])
		if err != nil {
			return nil, err
		}
		if err := c.addHop(keys); err != nil {
			return nil, err
		}
	}
	ok = true
	return c, nil
}

func (c *Circuit) addHop(keys route.Keys) error {
	f, err := route.NewLayer(keys.Fwd[:])
	if err != nil {
		return err
	}
	b, err := route.NewLayer(keys.Bwd[:])
	if err != nil {
		return err
	}
	c.fwd = append(c.fwd, f)
	c.bwd = append(c.bwd, b)
	return nil
}

// sealToHop builds a relay-cell body terminating at hop target: hops before
// it get tagForward, target gets tagTerminate and the payload.
func (c *Circuit) sealToHop(target int, payload []byte) []byte {
	b := c.fwd[target].Seal(append([]byte{tagTerminate}, payload...))
	for i := target - 1; i >= 0; i-- {
		b = c.fwd[i].Seal(append([]byte{tagForward}, b...))
	}
	return b
}

// openFromHop peels a backward cell that originated at hop target.
func (c *Circuit) openFromHop(target int, body []byte) ([]byte, error) {
	b := body
	for i := 0; i <= target; i++ {
		var err error
		if b, err = c.bwd[i].Open(b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// exitCmd sends a relay command that terminates at the exit hop.
func (c *Circuit) exitCmd(cmd byte, payload []byte) error {
	last := len(c.fwd) - 1
	body := c.sealToHop(last, append([]byte{cmd}, payload...))
	return c.conn.write(route.Cell{Cmd: route.CmdRelay, Body: body})
}

// recvExit reads one backward cell and peels it back to the exit hop's
// marker byte and payload.
func (c *Circuit) recvExit() (marker byte, payload []byte, err error) {
	resp, err := c.conn.read()
	if err != nil {
		return 0, nil, err
	}
	if resp.Cmd != route.CmdRelay {
		return 0, nil, errors.New("route: expected relay cell")
	}
	inner, err := c.openFromHop(len(c.bwd)-1, resp.Body)
	if err != nil {
		return 0, nil, err
	}
	if len(inner) < 1 {
		return 0, nil, errShort
	}
	return inner[0], inner[1:], nil
}

// Send passes a payload to the exit hop and returns its reply.
func (c *Circuit) Send(payload []byte) ([]byte, error) {
	if err := c.exitCmd(cmdData, payload); err != nil {
		return nil, err
	}
	m, reply, err := c.recvExit()
	if err != nil {
		return nil, err
	}
	if m != mkData {
		return nil, errors.New("route: expected data reply")
	}
	return reply, nil
}

// EstablishRendezvous parks this circuit at its exit hop under cookie, so a
// land's half-circuit can later be spliced to it. The exit hop is the
// rendezvous relay; it never learns either endpoint.
func (c *Circuit) EstablishRendezvous(cookie []byte) error {
	if err := c.exitCmd(cmdRendezvous, cookie); err != nil {
		return err
	}
	m, _, err := c.recvExit()
	if err != nil {
		return err
	}
	if m != mkRvEstablished {
		return errors.New("route: rendezvous not established")
	}
	return nil
}

// JoinRendezvous splices this circuit to the one waiting at the exit hop
// under cookie.
func (c *Circuit) JoinRendezvous(cookie []byte) error {
	if err := c.exitCmd(cmdRendezvousJoin, cookie); err != nil {
		return err
	}
	m, _, err := c.recvExit()
	if err != nil {
		return err
	}
	if m != mkRvJoined {
		return errors.New("route: rendezvous join failed")
	}
	return nil
}

// SendRv sends a payload to the spliced peer across the rendezvous.
func (c *Circuit) SendRv(payload []byte) error { return c.exitCmd(cmdData, payload) }

// RecvRv waits for the next payload from the spliced peer.
func (c *Circuit) RecvRv() ([]byte, error) {
	m, payload, err := c.recvExit()
	if err != nil {
		return nil, err
	}
	if m != mkData {
		return nil, errors.New("route: expected peer data")
	}
	return payload, nil
}

// EstablishIntro registers this circuit at its exit hop as an introduction
// point for a land identified by routePub. The exit hop then forwards any
// INTRODUCE for that land down this circuit.
func (c *Circuit) EstablishIntro(routePub []byte) error {
	if err := c.exitCmd(cmdIntroEstablish, routePub); err != nil {
		return err
	}
	m, _, err := c.recvExit()
	if err != nil {
		return err
	}
	if m != mkIntroReady {
		return errors.New("route: intro point not established")
	}
	return nil
}

// RecvIntroduce waits for the next INTRODUCE sealed box forwarded by the
// introduction point. The land opens it with its route private key.
func (c *Circuit) RecvIntroduce() ([]byte, error) {
	m, payload, err := c.recvExit()
	if err != nil {
		return nil, err
	}
	if m != mkIntroduce {
		return nil, errors.New("route: expected introduce")
	}
	return payload, nil
}

// Introduce asks the introduction point at this circuit's exit hop to deliver
// a sealed INTRODUCE box to the land registered under introKey.
func (c *Circuit) Introduce(introKey, sealed []byte) error {
	if err := c.exitCmd(cmdIntroduce, buildIntroduce(introKey, sealed)); err != nil {
		return err
	}
	m, _, err := c.recvExit()
	if err != nil {
		return err
	}
	if m != mkIntroAck {
		return errors.New("route: introduce not delivered")
	}
	return nil
}

// Close tears the circuit down.
func (c *Circuit) Close() error {
	_ = c.conn.write(route.Cell{Cmd: route.CmdDestroy})
	return c.conn.s.Close()
}
