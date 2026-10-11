package board

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
)

const testCID = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"

func testManifest(mod ed25519.PrivateKey) *manifest.Payload {
	l := manifest.DefaultLimits
	l.PoWBits = 4
	l.BumpLimit = 3
	l.ThreadsPerPage = 2
	l.Pages = 1
	l.OPImageRequired = false
	m := &manifest.Payload{
		Network: "testnet", Seq: 1, Threshold: 1,
		Boards: []manifest.Board{{ID: "linux", Title: "Linux"}, {ID: "dev", Title: "Dev"}},
		Limits: l,
	}
	if mod != nil {
		m.Moderators = []keys.PublicKey{keys.Public(mod)}
	}
	return m
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	sk, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func newStore(t *testing.T, m *manifest.Payload) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"), m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func op(t *testing.T, secret ed25519.PrivateKey, m *manifest.Payload, body string, at int64) *Post {
	t.Helper()
	p := &Post{Board: "linux", Subject: "subj", Body: body, Time: at}
	if err := p.Seal(secret, nil, m.Limits.PoWBits); err != nil {
		t.Fatal(err)
	}
	return p
}

func reply(t *testing.T, secret ed25519.PrivateKey, m *manifest.Payload, thread *Post, body string, at int64, sage bool) *Post {
	t.Helper()
	p := &Post{Board: thread.Board, Thread: thread.ID(), Body: body, Time: at, Sage: sage}
	if err := p.Seal(secret, thread.ThreadSalt, m.Limits.PoWBits); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealAndValidate(t *testing.T) {
	m := testManifest(nil)
	secret := mustKey(t)
	now := time.Now()
	p := op(t, secret, m, "hello", now.Unix())
	if err := p.Validate(m, now); err != nil {
		t.Fatalf("valid post rejected: %v", err)
	}
	parsed, err := ParsePost(p.Encode())
	if err != nil || parsed.ID() != p.ID() {
		t.Fatalf("round trip: %v", err)
	}

	tampered := *p
	tampered.Body = "goodbye"
	if err := tampered.Validate(m, now); err == nil {
		t.Fatal("edited post accepted")
	}

	strict := *m
	strict.Limits.PoWBits = 24
	if err := p.Validate(&strict, now); err == nil {
		t.Fatal("post with too little work accepted")
	}

	future := op(t, secret, m, "from the future", now.Add(time.Hour).Unix())
	if err := future.Validate(m, now); err == nil {
		t.Fatal("future post accepted")
	}

	wrongBoard := &Post{Board: "nope", Body: "x", Time: now.Unix()}
	_ = wrongBoard.Seal(secret, nil, 4)
	if err := wrongBoard.Validate(m, now); err == nil {
		t.Fatal("post to unknown board accepted")
	}
}

func TestPosterIDStableInThreadUnlinkableAcross(t *testing.T) {
	m := testManifest(nil)
	secret := mustKey(t)
	now := time.Now().Unix()
	t1 := op(t, secret, m, "a", now)
	t2 := op(t, secret, m, "b", now)
	r1 := reply(t, secret, m, t1, "c", now, false)
	if r1.PosterID() != t1.PosterID() {
		t.Fatal("same poster got different IDs in one thread")
	}
	if t1.PosterID() == t2.PosterID() {
		t.Fatal("same poster linkable across threads")
	}
	other := reply(t, mustKey(t), m, t1, "d", now, false)
	if other.PosterID() == t1.PosterID() {
		t.Fatal("different posters share an ID")
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	m := testManifest(nil)
	p := op(t, mustKey(t), m, "hi", time.Now().Unix())
	enc := string(p.Encode())
	if _, err := ParsePost([]byte(" " + enc)); err == nil {
		t.Fatal("leading whitespace accepted")
	}
	if _, err := ParsePost([]byte(strings.Replace(enc, `"v":1`, `"v":1,"x":2`, 1))); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestBumpOrderSageAndPrune(t *testing.T) {
	m := testManifest(nil) // 2 threads max, bump limit 3
	s := newStore(t, m)
	secret := mustKey(t)
	base := time.Now().Add(-time.Hour).Unix()
	now := time.Now()

	a := op(t, secret, m, "a", base)
	b := op(t, secret, m, "b", base+1)
	for _, p := range []*Post{a, b} {
		if _, err := s.Add(p, now); err != nil {
			t.Fatal(err)
		}
	}
	order := func() []string {
		ts, _ := s.Page("linux", 0, 0)
		var ids []string
		for _, tv := range ts {
			ids = append(ids, tv.OP.Body)
		}
		return ids
	}
	if got := strings.Join(order(), ""); got != "ba" {
		t.Fatalf("order %q, want ba", got)
	}
	// A sage reply does not bump.
	if _, err := s.Add(reply(t, secret, m, a, "sage", base+2, true), now); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order(), ""); got != "ba" {
		t.Fatalf("sage bumped: %q", got)
	}
	// A normal reply does.
	if _, err := s.Add(reply(t, secret, m, a, "bump", base+3, false), now); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order(), ""); got != "ab" {
		t.Fatalf("reply did not bump: %q", got)
	}
	// A third thread pushes b off the board.
	c := op(t, secret, m, "c", base+4)
	if _, err := s.Add(c, now); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order(), ""); got != "ca" {
		t.Fatalf("after prune %q, want ca", got)
	}
	// b cannot come back, and nor can replies to it.
	if _, err := s.Add(b, now); !errors.Is(err, ErrPruned) {
		t.Fatalf("pruned thread re-added: %v", err)
	}
	if _, err := s.Add(reply(t, secret, m, b, "late", base+5, false), now); !errors.Is(err, ErrPruned) {
		t.Fatalf("reply to pruned thread: %v", err)
	}
}

func TestBumpLimit(t *testing.T) {
	m := testManifest(nil)
	s := newStore(t, m)
	secret := mustKey(t)
	base := time.Now().Add(-time.Hour).Unix()
	a := op(t, secret, m, "a", base)
	s.Add(a, time.Now())
	for i := range 3 {
		s.Add(reply(t, secret, m, a, "r", base+int64(i)+1, false), time.Now())
	}
	tv, _ := s.Thread(a.ID())
	if tv.Bump != base+3 || !tv.BumpLimitHit {
		t.Fatalf("bump %d limit %v", tv.Bump-base, tv.BumpLimitHit)
	}
	s.Add(reply(t, secret, m, a, "past limit", base+10, false), time.Now())
	tv, _ = s.Thread(a.ID())
	if tv.Bump != base+3 {
		t.Fatal("reply past the bump limit bumped the thread")
	}
}

func TestOrphanReplyAttachesWhenOPArrives(t *testing.T) {
	m := testManifest(nil)
	s := newStore(t, m)
	secret := mustKey(t)
	now := time.Now()
	a := op(t, secret, m, "a", now.Unix()-10)
	r := reply(t, secret, m, a, "early", now.Unix()-5, false)
	if _, err := s.Add(r, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Thread(a.ID()); ok {
		t.Fatal("thread exists without opener")
	}
	s.Add(a, now)
	tv, ok := s.Thread(a.ID())
	if !ok || len(tv.Replies) != 1 {
		t.Fatalf("orphan not attached: ok=%v replies=%d", ok, len(tv.Replies))
	}
}

func TestTombstones(t *testing.T) {
	mod := mustKey(t)
	m := testManifest(mod)
	s := newStore(t, m)
	secret := mustKey(t)
	now := time.Now()
	a := op(t, secret, m, "a", now.Unix()-10)
	a.Image = nil
	r := reply(t, secret, m, a, "bad reply", now.Unix()-5, false)
	s.Add(a, now)
	s.Add(r, now)

	fake := &Tombstone{Target: r.ID(), Board: "linux", Time: now.Unix()}
	fake.Sign(mustKey(t))
	if _, err := s.AddTombstone(fake); err == nil {
		t.Fatal("tombstone from non-moderator accepted")
	}

	ts := &Tombstone{Target: r.ID(), Board: "linux", Time: now.Unix(), Reason: "spam"}
	ts.Sign(mod)
	if _, err := s.AddTombstone(ts); err != nil {
		t.Fatal(err)
	}
	tv, _ := s.Thread(a.ID())
	if len(tv.Replies) != 0 {
		t.Fatal("reply not removed")
	}
	if _, err := s.Add(r, now); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted reply re-added: %v", err)
	}

	whole := &Tombstone{Target: a.ID(), Board: "linux", Time: now.Unix()}
	whole.Sign(mod)
	if _, err := s.AddTombstone(whole); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Thread(a.ID()); ok {
		t.Fatal("thread not removed")
	}
	if _, err := s.Add(reply(t, secret, m, a, "late", now.Unix(), false), now); !errors.Is(err, ErrDeleted) {
		t.Fatalf("reply to deleted thread: %v", err)
	}
}

func TestBlobRefsFreed(t *testing.T) {
	mod := mustKey(t)
	m := testManifest(mod)
	s := newStore(t, m)
	now := time.Now()
	p := &Post{Board: "linux", Body: "pic", Time: now.Unix(), Image: &ImageRef{
		CID: testCID, ThumbCID: testCID, Mime: "image/png", Width: 1, Height: 1, Size: 10,
	}}
	if err := p.Seal(mustKey(t), nil, m.Limits.PoWBits); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(p, now); err != nil {
		t.Fatal(err)
	}
	if !s.Referenced(testCID) {
		t.Fatal("blob not referenced")
	}
	ts := &Tombstone{Target: p.ID(), Board: "linux", Time: now.Unix()}
	ts.Sign(mod)
	res, err := s.AddTombstone(ts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Freed) == 0 || s.Referenced(testCID) {
		t.Fatalf("blob not freed: %v", res.Freed)
	}
}

func TestPersistence(t *testing.T) {
	mod := mustKey(t)
	m := testManifest(mod)
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path, m)
	if err != nil {
		t.Fatal(err)
	}
	secret := mustKey(t)
	now := time.Now()
	a := op(t, secret, m, "a", now.Unix()-10)
	r := reply(t, secret, m, a, "r", now.Unix()-5, false)
	s.Add(a, now)
	s.Add(r, now)
	ts := &Tombstone{Target: r.ID(), Board: "linux", Time: now.Unix()}
	ts.Sign(mod)
	s.AddTombstone(ts)
	s.Close()

	s2, err := Open(path, m)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	tv, ok := s2.Thread(a.ID())
	if !ok || len(tv.Replies) != 0 {
		t.Fatalf("reload: ok=%v replies=%d", ok, len(tv.Replies))
	}
	if !s2.Has(r.ID()) {
		t.Fatal("tombstone forgotten after reload")
	}
}

func TestDigestsMatchAfterSameInserts(t *testing.T) {
	m := testManifest(nil)
	s1, s2 := newStore(t, m), newStore(t, m)
	secret := mustKey(t)
	now := time.Now()
	a := op(t, secret, m, "a", now.Unix()-10)
	r := reply(t, secret, m, a, "r", now.Unix()-5, false)
	s1.Add(a, now)
	s1.Add(r, now)
	s2.Add(r, now) // different order
	s2.Add(a, now)
	d1, d2 := s1.Digests("linux"), s2.Digests("linux")
	if len(d1) != 1 || len(d2) != 1 || string(d1[0].Hash) != string(d2[0].Hash) {
		t.Fatal("digests differ for identical content")
	}
}

func FuzzParsePost(f *testing.F) {
	f.Add([]byte(`{"v":1,"board":"linux","body":"x","time":1,"author":"","nonce":0}`))
	m := testManifest(nil)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePost(b)
		if err != nil {
			return
		}
		_ = p.Validate(m, time.Now())
		_ = p.ID()
	})
}

// Two nodes that receive the same posts in a different order prune
// different threads. Each must then treat its pruned thread as settled, or
// every sync fetches the peer's copy again only to reject it.
func TestPruneOrderDivergenceIsSettled(t *testing.T) {
	m := testManifest(nil) // two threads per board
	secret := mustKey(t)
	now := time.Now()
	a, b := newStore(t, m), newStore(t, m)
	x := op(t, secret, m, "x", now.Unix()-30)
	y := op(t, secret, m, "y", now.Unix()-20)
	fresh := op(t, secret, m, "new", now.Unix()-10)
	bumpX := reply(t, secret, m, x, "bump", now.Unix()-5, false)
	for _, s := range []*Store{a, b} {
		s.Add(x, now)
		s.Add(y, now)
	}
	a.Add(fresh, now)
	a.Add(bumpX, now) // X already pruned on A
	b.Add(bumpX, now)
	b.Add(fresh, now) // Y pruned on B

	if _, ok := a.Thread(x.ID()); ok {
		t.Fatal("A should have pruned X")
	}
	if _, ok := b.Thread(y.ID()); ok {
		t.Fatal("B should have pruned Y")
	}
	if !a.Settled(x.ID()) || !b.Settled(y.ID()) {
		t.Error("pruned thread not settled")
	}
	if a.Settled(y.ID()) || a.Settled(fresh.ID()) {
		t.Error("live thread reported settled")
	}
}

func TestSettledFullAndDeleted(t *testing.T) {
	mod := mustKey(t)
	m := testManifest(mod)
	secret := mustKey(t)
	now := time.Now()
	s := newStore(t, m)
	th := op(t, secret, m, "thread", now.Unix()-100)
	s.Add(th, now)
	for i := range 2 * m.Limits.BumpLimit {
		if _, err := s.Add(reply(t, secret, m, th, "r"+string(rune('a'+i)), now.Unix()-50+int64(i), false), now); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Settled(th.ID()) {
		t.Error("full thread not settled")
	}
	gone := op(t, secret, m, "gone", now.Unix())
	s.Add(gone, now)
	ts := &Tombstone{Target: gone.ID(), Board: "linux", Time: now.Unix()}
	ts.Sign(mod)
	if _, err := s.AddTombstone(ts); err != nil {
		t.Fatal(err)
	}
	if !s.Settled(gone.ID()) {
		t.Error("deleted thread not settled")
	}
}
