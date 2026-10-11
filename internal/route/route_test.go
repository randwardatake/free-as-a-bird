package route

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func relayKey(t *testing.T) (id []byte, sk *ecdh.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, err = DHKeyFromSeed(priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	return pub, sk
}

func TestDHKeyDeterministic(t *testing.T) {
	_, sk := ed25519KeyPair(t)
	a, err := DHKeyFromSeed(sk.Seed())
	if err != nil {
		t.Fatal(err)
	}
	b, err := DHKeyFromSeed(sk.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey().Bytes(), b.PublicKey().Bytes()) {
		t.Fatal("route key not deterministic from node seed")
	}
}

func ed25519KeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestHandshake(t *testing.T) {
	id, sk := relayKey(t)

	cs, create, err := CreateClient(id, sk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	created, serverKeys, err := ServerHandshake(id, sk, create)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := cs.Finish(created)
	if err != nil {
		t.Fatal(err)
	}
	if clientKeys != serverKeys {
		t.Fatal("client and server derived different keys")
	}
}

func TestHandshakeRejectsWrongRelayKey(t *testing.T) {
	id, sk := relayKey(t)
	_, other := relayKey(t)

	cs, create, err := CreateClient(id, other.PublicKey()) // client thinks relay has a different key
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := ServerHandshake(id, sk, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Finish(created); err == nil {
		t.Fatal("accepted handshake with impostor relay key")
	}
}

func TestHandshakeRejectsWrongID(t *testing.T) {
	id, sk := relayKey(t)
	wrongID, _ := relayKey(t)

	cs, create, err := CreateClient(wrongID, sk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := ServerHandshake(id, sk, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Finish(created); err == nil {
		t.Fatal("accepted handshake with mismatched relay id")
	}
}

func TestCellRoundTrip(t *testing.T) {
	c := Cell{Cmd: CmdRelay, Body: []byte("hello circuit")}
	for i := range c.Circ {
		c.Circ[i] = byte(i)
	}
	buf, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != CellSize {
		t.Fatalf("marshalled cell is %d bytes, want %d", len(buf), CellSize)
	}
	got, err := ParseCell(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmd != c.Cmd || got.Circ != c.Circ || !bytes.Equal(got.Body, c.Body) {
		t.Fatalf("cell round trip mismatch: %+v vs %+v", got, c)
	}
}

func TestCellBodyTooLong(t *testing.T) {
	if _, err := (Cell{Body: make([]byte, MaxCellBody+1)}).Marshal(); err == nil {
		t.Fatal("oversized cell body accepted")
	}
}

// buildCircuit runs full handshakes for n relays and returns the client-side
// send layers (forward) and each relay's open layer (its forward key).
func buildCircuit(t *testing.T, n int) (send []*Layer, relays []*Layer) {
	t.Helper()
	for i := 0; i < n; i++ {
		id, sk := relayKey(t)
		cs, create, err := CreateClient(id, sk.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		created, sKeys, err := ServerHandshake(id, sk, create)
		if err != nil {
			t.Fatal(err)
		}
		cKeys, err := cs.Finish(created)
		if err != nil {
			t.Fatal(err)
		}
		cl, err := NewLayer(cKeys.Fwd[:])
		if err != nil {
			t.Fatal(err)
		}
		rl, err := NewLayer(sKeys.Fwd[:])
		if err != nil {
			t.Fatal(err)
		}
		send = append(send, cl)
		relays = append(relays, rl)
	}
	return send, relays
}

func TestOnionPeeling(t *testing.T) {
	send, relays := buildCircuit(t, 3)
	msg := []byte("to the last hop")

	wrapped := WrapOnion(send, msg)

	// Each relay peels its layer in order; the last hop sees the plaintext.
	b := wrapped
	for i, r := range relays {
		var err error
		b, err = r.Open(b)
		if err != nil {
			t.Fatalf("hop %d failed to peel: %v", i, err)
		}
	}
	if !bytes.Equal(b, msg) {
		t.Fatalf("final plaintext %q != %q", b, msg)
	}
}

func TestOnionTamperDetected(t *testing.T) {
	send, relays := buildCircuit(t, 2)
	wrapped := WrapOnion(send, []byte("payload"))
	wrapped[0] ^= 0xff // flip a byte in the outer layer
	if _, err := relays[0].Open(wrapped); err == nil {
		t.Fatal("tampered onion layer opened without error")
	}
}

func TestLayerNonceStepsInLockstep(t *testing.T) {
	// Two layers with the same key stand in for the two ends of one hop.
	key := make([]byte, 32)
	rand.Read(key)
	tx, err := NewLayer(key)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := NewLayer(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		msg := []byte{byte(i), byte(i + 1)}
		got, err := rx.Open(tx.Seal(msg))
		if err != nil {
			t.Fatalf("cell %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("cell %d: got %x want %x", i, got, msg)
		}
	}
}

func FuzzParseCell(f *testing.F) {
	for _, body := range [][]byte{nil, []byte("x"), make([]byte, MaxCellBody)} {
		if b, err := (Cell{Cmd: CmdRelay, Body: body}).Marshal(); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		c, err := ParseCell(buf)
		if err != nil {
			return
		}
		// The parser tolerates arbitrary padding after the body (it is cover
		// traffic, not signed), so it need not reproduce the input bytes.
		// What must hold: the body never exceeds the cell, and the structured
		// form is stable — marshalling a parsed cell and parsing it again
		// yields an identical cell.
		if len(c.Body) > MaxCellBody {
			t.Fatalf("parsed body length %d exceeds %d", len(c.Body), MaxCellBody)
		}
		re, err := c.Marshal()
		if err != nil {
			t.Fatalf("re-marshal of parsed cell failed: %v", err)
		}
		c2, err := ParseCell(re)
		if err != nil {
			t.Fatalf("re-parse of marshalled cell failed: %v", err)
		}
		if c.Cmd != c2.Cmd || c.Circ != c2.Circ || !bytes.Equal(c.Body, c2.Body) {
			t.Fatal("parse/marshal is not idempotent on the structured form")
		}
	})
}

func TestSealedBox(t *testing.T) {
	_, sk := relayKey(t)
	msg := []byte("rendezvous at R with cookie abc")
	sealed, err := SealTo(sk.PublicKey(), msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSealed(sk, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("sealed box round trip: %q != %q", got, msg)
	}
	// A different key cannot open it.
	_, other := relayKey(t)
	if _, err := OpenSealed(other, sealed); err == nil {
		t.Fatal("sealed box opened by wrong key")
	}
	// Tampering is detected.
	sealed[len(sealed)-1] ^= 0xff
	if _, err := OpenSealed(sk, sealed); err == nil {
		t.Fatal("tampered sealed box opened")
	}
}
