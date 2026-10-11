package land

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
)

func newKeys(t *testing.T, n int) []ed25519.PrivateKey {
	t.Helper()
	out := make([]ed25519.PrivateKey, n)
	for i := range out {
		sk, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = sk
	}
	return out
}

func peerID(t testing.TB) string {
	t.Helper()
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func testManifest(maint []ed25519.PrivateKey, threshold int) *manifest.Payload {
	p := &manifest.Payload{Network: "testnet", Threshold: threshold}
	for _, sk := range maint {
		p.Maintainers = append(p.Maintainers, keys.Public(sk))
	}
	return p
}

func newMaster(t *testing.T) *Master {
	t.Helper()
	m, err := NewMaster(Words24)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func record(t testing.TB, m *Master, seq uint64) *Record {
	t.Helper()
	return &Record{Payload: Payload{
		Network: "testnet",
		Name:    "randward",
		Group:   "freeasabird",
		Seq:     seq,
		Time:    1760000000,
		Land:    keys.Public(m.LandKey()),
		Route: Route{
			RoutePub:  RoutePubOf(m.RouteKey()),
			Anonymous: true,
			Intro:     []string{peerID(t), peerID(t)},
			PoWBits:   16,
		},
	}}
}

func TestVerify(t *testing.T) {
	maint := newKeys(t, 3)
	mf := testManifest(maint, 2)
	owner := newMaster(t)

	r := record(t, owner, 1)
	r.Sign(maint[0])
	r.Sign(maint[1])
	if err := r.Verify(mf); err == nil {
		t.Fatal("record without the land key's signature accepted")
	}
	r.Sign(owner.LandKey())
	if err := r.Verify(mf); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if r.Payload.Host() != "randward.freeasabird" {
		t.Fatalf("Host() = %q", r.Payload.Host())
	}

	// Below threshold, and duplicate signatures must not count twice.
	r = record(t, owner, 1)
	r.Sign(owner.LandKey())
	r.Sign(maint[0])
	r.Signatures = append(r.Signatures, r.Signatures[1])
	if err := r.Verify(mf); err == nil {
		t.Fatal("1 of 2 maintainer signatures accepted")
	}

	// A non-maintainer's signature does not count.
	r.Sign(newKeys(t, 1)[0])
	if err := r.Verify(mf); err == nil {
		t.Fatal("outsider signature counted toward threshold")
	}

	// Editing a signed payload invalidates every signature.
	r = record(t, owner, 1)
	for _, sk := range []ed25519.PrivateKey{owner.LandKey(), maint[0], maint[1]} {
		r.Sign(sk)
	}
	r.Payload.Route.PoWBits++
	if err := r.Verify(mf); err == nil {
		t.Fatal("edited record accepted")
	}
	// Re-signing after the edit drops the stale signatures.
	r.Sign(owner.LandKey())
	if len(r.Signatures) != 1 {
		t.Fatalf("stale signatures kept: %d", len(r.Signatures))
	}

	// Records are bound to their network.
	r = record(t, owner, 1)
	r.Payload.Network = "othernet"
	for _, sk := range []ed25519.PrivateKey{owner.LandKey(), maint[0], maint[1]} {
		r.Sign(sk)
	}
	if err := r.Verify(mf); err == nil {
		t.Fatal("record for another network accepted")
	}
}

func TestValidate(t *testing.T) {
	owner := newMaster(t)
	pid := peerID(t)
	cases := map[string]func(p *Payload){
		"empty name":          func(p *Payload) { p.Name = "" },
		"uppercase name":      func(p *Payload) { p.Name = "Randward" },
		"dotted name":         func(p *Payload) { p.Name = "a.b" },
		"leading hyphen":      func(p *Payload) { p.Name = "-a" },
		"trailing hyphen":     func(p *Payload) { p.Group = "a-" },
		"long name":           func(p *Payload) { p.Name = strings.Repeat("a", 33) },
		"zero seq":            func(p *Payload) { p.Seq = 0 },
		"short land key":      func(p *Payload) { p.Land = p.Land[:31] },
		"short route key":     func(p *Payload) { p.Route.RoutePub = p.Route.RoutePub[:31] },
		"negative pow":        func(p *Payload) { p.Route.PoWBits = -1 },
		"huge pow":            func(p *Payload) { p.Route.PoWBits = 33 },
		"anonymous, no intro": func(p *Payload) { p.Route.Intro = nil },
		"direct with intro":   func(p *Payload) { p.Route.Anonymous = false },
		"bad intro":           func(p *Payload) { p.Route.Intro[0] = "not-a-peer" },
		"duplicate intro":     func(p *Payload) { p.Route.Intro = []string{pid, pid} },
		"too many intro": func(p *Payload) {
			for len(p.Route.Intro) <= MaxIntro {
				p.Route.Intro = append(p.Route.Intro, peerID(t))
			}
		},
	}
	for name, mutate := range cases {
		r := record(t, owner, 1)
		mutate(&r.Payload)
		if err := r.Payload.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	r := record(t, owner, 1)
	r.Payload.Route.Anonymous = false
	r.Payload.Route.Intro = nil
	if err := r.Payload.Validate(); err != nil {
		t.Fatalf("direct land rejected: %v", err)
	}
	r.Payload.Name = "a-1"
	if err := r.Payload.Validate(); err != nil {
		t.Fatalf("name with inner hyphen rejected: %v", err)
	}
}

func TestVerifyUpdate(t *testing.T) {
	maint := newKeys(t, 2)
	mf := testManifest(maint, 1)
	owner, thief := newMaster(t), newMaster(t)
	sign := func(r *Record, sks ...ed25519.PrivateKey) *Record {
		for _, sk := range sks {
			r.Sign(sk)
		}
		return r
	}
	cur := sign(record(t, owner, 1), owner.LandKey(), maint[0])

	// The owner updates its own descriptor.
	next := sign(record(t, owner, 2), owner.LandKey(), maint[1])
	if err := VerifyUpdate(mf, cur, next); err != nil {
		t.Fatalf("owner update rejected: %v", err)
	}
	if err := VerifyUpdate(mf, next, cur); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("older record: got %v, want ErrNotNewer", err)
	}
	if err := VerifyUpdate(mf, cur, cur); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("same seq: got %v, want ErrNotNewer", err)
	}

	// A maintainer-signed record for a different key, without the current
	// owner's signature, must not take the name.
	stolen := sign(record(t, thief, 2), thief.LandKey(), maint[0], maint[1])
	if err := VerifyUpdate(mf, cur, stolen); err == nil {
		t.Fatal("name moved to a new key without the owner's signature")
	}
	// The owner rotating to a new key co-signs with the old one.
	rotated := sign(record(t, thief, 2), thief.LandKey(), owner.LandKey(), maint[0])
	if err := VerifyUpdate(mf, cur, rotated); err != nil {
		t.Fatalf("owner-signed rotation rejected: %v", err)
	}

	other := record(t, owner, 2)
	other.Payload.Name = "someoneelse"
	sign(other, owner.LandKey(), maint[0])
	if err := VerifyUpdate(mf, cur, other); err == nil {
		t.Fatal("record for a different name accepted as an update")
	}
}

func TestParseRoundTrip(t *testing.T) {
	maint := newKeys(t, 1)
	owner := newMaster(t)
	r := record(t, owner, 7)
	r.Sign(owner.LandKey())
	r.Sign(maint[0])
	enc := r.Marshal()
	got, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), enc) {
		t.Fatalf("round trip changed record:\n%s\n%s", enc, got.Marshal())
	}
	if err := got.Verify(testManifest(maint, 1)); err != nil {
		t.Fatalf("parsed record does not verify: %v", err)
	}
	if !got.Payload.Route.RoutePub.Equal(RoutePubOf(owner.RouteKey())) {
		t.Fatal("route key changed in round trip")
	}

	for name, b := range map[string][]byte{
		"unknown field": bytes.Replace(enc, []byte(`"seq"`), []byte(`"extra": 1, "seq"`), 1),
		"trailing data": append(append([]byte{}, enc...), "{}"...),
		"too large":     make([]byte, MaxRecordSize+1),
		"bad route key": bytes.Replace(enc, []byte(r.Payload.Route.RoutePub.String()), []byte("AAAA"), 1),
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	owner, _ := NewMaster(Words12)
	r := record(f, owner, 1)
	r.Sign(owner.LandKey())
	f.Add(r.Marshal())
	r.Payload.Route.Anonymous, r.Payload.Route.Intro = false, nil
	r.Sign(owner.LandKey())
	f.Add(r.Marshal())
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Parse(b)
		if err != nil {
			return
		}
		_ = r.Verify(&manifest.Payload{Network: r.Payload.Network, Threshold: 1, Maintainers: []keys.PublicKey{r.Payload.Land}})
		// Whitespace and field order may differ from the input, but a parsed
		// record must re-encode to something that parses to the same record.
		enc := r.Marshal()
		if len(enc) > MaxRecordSize {
			return // indentation can push a record that was just under the limit over it
		}
		r2, err := Parse(enc)
		if err != nil {
			t.Fatalf("re-parse of marshalled record failed: %v", err)
		}
		if !bytes.Equal(r2.Marshal(), enc) {
			t.Fatal("parse/marshal is not stable")
		}
	})
}
