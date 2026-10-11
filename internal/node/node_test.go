package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/randwardatake/free-as-a-bird/internal/board"
	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
	"github.com/randwardatake/free-as-a-bird/internal/media"
)

type testNet struct {
	t     *testing.T
	maint ed25519.PrivateKey
	mod   ed25519.PrivateKey
	gen   *manifest.Signed
}

func newTestNet(t *testing.T) *testNet {
	t.Helper()
	maint, _ := keys.Generate()
	mod, _ := keys.Generate()
	l := manifest.DefaultLimits
	l.PoWBits = 6
	gen := &manifest.Signed{Payload: manifest.Payload{
		Network: "testnet", Seq: 1, Threshold: 1,
		Maintainers: []keys.PublicKey{keys.Public(maint)},
		Moderators:  []keys.PublicKey{keys.Public(mod)},
		Boards:      []manifest.Board{{ID: "linux", Title: "Linux"}},
		Limits:      l,
	}}
	gen.Sign(maint)
	return &testNet{t: t, maint: maint, mod: mod, gen: gen}
}

func (tn *testNet) start(name string) *Node {
	tn.t.Helper()
	return tn.startWith(name, nil)
}

// startWith starts a node; edit, if not nil, adjusts its config first.
func (tn *testNet) startWith(name string, edit func(*Config)) *Node {
	t := tn.t
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), tn.gen.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})).With("node", name)
	}
	cfg := Config{
		DataDir:     dir,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		Logger:      log,
	}
	if edit != nil {
		edit(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func link(t *testing.T, a, b *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Connect(ctx, b.Addrs()[0]); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func waitMesh(t *testing.T, n *Node, board string) {
	t.Helper()
	eventually(t, "gossip mesh", func() bool {
		return len(n.ps.ListPeers(n.topicName("board/"+board))) > 0
	})
}

func testImage(t *testing.T) *media.Result {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for i := range img.Pix {
		img.Pix[i] = byte(i)
	}
	img.Set(0, 0, color.White)
	var buf bytes.Buffer
	png.Encode(&buf, img)
	res, err := media.Process(buf.Bytes(), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func postWithImage(t *testing.T, n *Node, body string) *board.Post {
	t.Helper()
	im := testImage(t)
	c, err := n.Blobs.Put(im.Data)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := n.Blobs.Put(im.Thumb)
	if err != nil {
		t.Fatal(err)
	}
	p := &board.Post{Board: "linux", Subject: "test", Body: body, Time: time.Now().Unix(),
		Image: &board.ImageRef{CID: c, ThumbCID: tc, Mime: im.Mime, Width: im.Width, Height: im.Height, Size: int64(len(im.Data))}}
	secret, _ := keys.Generate()
	if err := p.Seal(secret, nil, n.Manifest().Payload.Limits.PoWBits); err != nil {
		t.Fatal(err)
	}
	if err := n.PublishPost(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGossipSyncBlobsAndTombstones runs real libp2p nodes on localhost in a
// line A - B - C, so C only hears about A's posts through B.
func TestGossipSyncBlobsAndTombstones(t *testing.T) {
	tn := newTestNet(t)
	a, b, c := tn.start("A"), tn.start("B"), tn.start("C")
	link(t, a, b)
	link(t, b, c)
	waitMesh(t, a, "linux")
	waitMesh(t, c, "linux")

	p := postWithImage(t, a, "hello from A")
	eventually(t, "post reaches C via B", func() bool { _, ok := c.Store.Thread(p.ID()); return ok })
	eventually(t, "C downloads image and thumbnail", func() bool {
		return c.Blobs.Has(p.Image.CID) && c.Blobs.Has(p.Image.ThumbCID)
	})

	// A tampered copy must never be accepted anywhere.
	evil := *p
	evil.Body = "edited by a host"
	if _, err := c.Store.Add(&evil, time.Now()); err == nil {
		t.Fatal("tampered post accepted")
	}

	// A late joiner D, connected only to C, catches up through sync.
	d := tn.start("D")
	link(t, d, c)
	eventually(t, "D syncs the thread", func() bool { _, ok := d.Store.Thread(p.ID()); return ok })
	eventually(t, "D fetches the image", func() bool { return d.Blobs.Has(p.Image.CID) })

	// A moderator deletes the thread from A; everyone drops post and image.
	ts := &board.Tombstone{Target: p.ID(), Board: "linux", Time: time.Now().Unix(), Reason: "test"}
	ts.Sign(tn.mod)
	if err := a.PublishTombstone(context.Background(), ts); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, b, c, d} {
		eventually(t, "thread deleted everywhere", func() bool {
			_, ok := n.Store.Thread(p.ID())
			return !ok && !n.Blobs.Has(p.Image.CID) && !n.Blobs.Has(p.Image.ThumbCID)
		})
	}

	// A node that was offline during the deletion learns it on reconnect.
	e := tn.start("E")
	if _, err := e.Store.Add(p, time.Now()); err != nil {
		t.Fatal(err)
	}
	link(t, e, d)
	eventually(t, "offline node applies the tombstone", func() bool { _, ok := e.Store.Thread(p.ID()); return !ok })
}

func TestManifestUpdateSpreads(t *testing.T) {
	tn := newTestNet(t)
	a, b := tn.start("A"), tn.start("B")
	link(t, a, b)
	eventually(t, "manifest mesh", func() bool { return len(a.ps.ListPeers(a.topicName("manifest"))) > 0 })

	next := &manifest.Signed{Payload: tn.gen.Payload}
	next.Payload.Seq = 2
	next.Payload.Boards = append(append([]manifest.Board{}, next.Payload.Boards...), manifest.Board{ID: "dev", Title: "Development"})
	next.Sign(tn.maint)
	if err := a.PublishManifest(context.Background(), next.Marshal()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B accepts manifest seq 2", func() bool { return b.Manifest().Payload.Seq == 2 })
	if _, ok := b.Manifest().Payload.Board("dev"); !ok {
		t.Fatal("new board missing on B")
	}

	// An update signed by someone else is refused.
	stranger, _ := keys.Generate()
	bad := &manifest.Signed{Payload: next.Payload}
	bad.Payload.Seq = 3
	bad.Sign(stranger)
	if err := b.AcceptManifest(bad.Marshal()); err == nil {
		t.Fatal("unsigned manifest update accepted")
	}
}
