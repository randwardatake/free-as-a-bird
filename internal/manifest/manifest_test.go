package manifest

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/randwardatake/p2psite/internal/keys"
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

func pubs(sks []ed25519.PrivateKey) []keys.PublicKey {
	out := make([]keys.PublicKey, len(sks))
	for i, sk := range sks {
		out[i] = keys.Public(sk)
	}
	return out
}

func genesis(t *testing.T, maint []ed25519.PrivateKey, threshold int) *Signed {
	t.Helper()
	s := &Signed{Payload: Payload{
		Network:     "testnet",
		Seq:         1,
		Threshold:   threshold,
		Maintainers: pubs(maint),
		Boards:      []Board{{ID: "linux", Title: "Linux"}},
		Limits:      DefaultLimits,
	}}
	return s
}

func TestGenesisThreshold(t *testing.T) {
	m := newKeys(t, 3)
	s := genesis(t, m, 2)
	s.Sign(m[0])
	if err := s.VerifyGenesis(); err == nil {
		t.Fatal("1 of 2 signatures accepted")
	}
	s.Sign(m[0]) // signing twice with the same key must not count twice
	if err := s.VerifyGenesis(); err == nil {
		t.Fatal("duplicate signature counted twice")
	}
	s.Sign(m[1])
	if err := s.VerifyGenesis(); err != nil {
		t.Fatalf("2 of 2 rejected: %v", err)
	}
}

func TestSignatureFromOutsiderIgnored(t *testing.T) {
	m := newKeys(t, 1)
	outsider := newKeys(t, 1)
	s := genesis(t, m, 1)
	s.Sign(outsider[0])
	if err := s.VerifyGenesis(); err == nil {
		t.Fatal("signature from a non-maintainer accepted")
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	m := newKeys(t, 1)
	s := genesis(t, m, 1)
	s.Sign(m[0])
	s.Payload.Boards = append(s.Payload.Boards, Board{ID: "evil", Title: "Evil"})
	if err := s.VerifyGenesis(); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestUpdateRules(t *testing.T) {
	m := newKeys(t, 3)
	cur := genesis(t, m, 2)
	cur.Sign(m[0])
	cur.Sign(m[1])

	next := genesis(t, m, 2)
	next.Payload.Seq = 2
	next.Sign(m[1])
	next.Sign(m[2])
	if err := VerifyUpdate(cur, next); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}

	old := genesis(t, m, 2)
	old.Payload.Seq = 1
	old.Sign(m[0])
	old.Sign(m[1])
	if err := VerifyUpdate(next, old); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("rollback: got %v, want ErrNotNewer", err)
	}

	// A new maintainer set signs its own update: not allowed, the current
	// maintainers must approve.
	stranger := newKeys(t, 2)
	hijack := genesis(t, stranger, 1)
	hijack.Payload.Seq = 99
	hijack.Sign(stranger[0])
	if err := VerifyUpdate(cur, hijack); err == nil {
		t.Fatal("update signed only by new maintainers accepted")
	}

	other := genesis(t, m, 2)
	other.Payload.Network = "othernet"
	other.Payload.Seq = 5
	other.Sign(m[0])
	other.Sign(m[1])
	if err := VerifyUpdate(cur, other); err == nil {
		t.Fatal("update for another network accepted")
	}
}

func TestKeyRotation(t *testing.T) {
	old := newKeys(t, 2)
	nu := newKeys(t, 2)
	cur := genesis(t, old, 2)
	cur.Sign(old[0])
	cur.Sign(old[1])

	next := genesis(t, nu, 1)
	next.Payload.Seq = 2
	next.Sign(old[0])
	next.Sign(old[1])
	if err := VerifyUpdate(cur, next); err == nil {
		t.Fatal("update not signed by the new maintainer set accepted")
	}
	next.Sign(nu[0])
	if err := VerifyUpdate(cur, next); err != nil {
		t.Fatalf("rotation rejected: %v", err)
	}
}

func TestParseRoundTrip(t *testing.T) {
	m := newKeys(t, 1)
	s := genesis(t, m, 1)
	s.Payload.Moderators = pubs(newKeys(t, 1))
	s.Sign(m[0])
	got, err := Parse(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyGenesis(); err != nil {
		t.Fatalf("round-tripped manifest invalid: %v", err)
	}
	if !got.Payload.IsModerator(s.Payload.Moderators[0]) {
		t.Fatal("moderator lost in round trip")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"payload":{},"signatures":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateBoardIDs(t *testing.T) {
	m := newKeys(t, 1)
	for _, id := range []string{"", "Linux", "a/b", "waytoolongid", "../x", "static", "blob"} {
		s := genesis(t, m, 1)
		s.Payload.Boards = []Board{{ID: id, Title: "x"}}
		if err := s.Payload.Validate(); err == nil {
			t.Errorf("board id %q accepted", id)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"payload":{"network":"a","seq":1,"threshold":1,"maintainers":[],"moderators":[],"boards":[],"limits":{}},"signatures":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Parse(b)
		if err != nil {
			return
		}
		_ = s.VerifyGenesis()
		_ = s.Marshal()
	})
}
