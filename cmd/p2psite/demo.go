package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"

	"github.com/randwardatake/p2psite/internal/board"
	"github.com/randwardatake/p2psite/internal/keys"
	"github.com/randwardatake/p2psite/internal/manifest"
	"github.com/randwardatake/p2psite/internal/media"
	"github.com/randwardatake/p2psite/internal/node"
)

const demoRules = `1. English only.
2. Stay on topic for each board.
3. No illegal content, no doxxing, no spam.
4. Moderators delete posts by signing a tombstone; every node then removes the post and its image.`

// cmdDemo runs several nodes in one process on loopback so the whole
// network can be tried on one machine.
func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	dir := fs.String("dir", "p2psite-demo", "directory for demo keys and node data")
	count := fs.Int("nodes", 3, "number of nodes (2-9)")
	webBase := fs.Int("web-port", 8081, "web UI port of the first node; the others count up")
	p2pBase := fs.Int("p2p-port", 4101, "peer port of the first node; the others count up")
	verbose := fs.Bool("v", false, "verbose logging")
	fs.Parse(args)
	if *count < 2 || *count > 9 {
		return errors.New("-nodes must be between 2 and 9")
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	fresh, err := prepareDemo(*dir, *count)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nodes := make([]*node.Node, *count)
	errc := make(chan error, *count)
	for i := range *count {
		ready := make(chan *node.Node, 1)
		o := nodeOpts{
			data: filepath.Join(*dir, fmt.Sprintf("node%d", i+1)),
			web:  fmt.Sprintf("127.0.0.1:%d", *webBase+i),
			listen: []string{
				fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", *p2pBase+i),
				fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", *p2pBase+i),
			},
			ready: ready,
		}
		if i == 0 {
			o.modKey = filepath.Join(*dir, "moderator.key")
		} else {
			// A line topology: node N only knows node N-1, so posts on the
			// last node reach the first one by hopping through the others.
			o.bootstrap = nodes[i-1].Addrs()[:1]
		}
		go func() { errc <- runNode(ctx, log.With("node", i+1), o) }()
		select {
		case nodes[i] = <-ready:
		case err := <-errc:
			return fmt.Errorf("node %d: %w", i+1, err)
		}
	}

	if fresh {
		log.Info("seeding sample threads")
		if err := seedDemo(ctx, nodes); err != nil {
			log.Warn("seeding failed", "err", err)
		}
	}

	fmt.Printf("\n  p2psite demo is running with %d nodes (Ctrl+C to stop)\n\n", *count)
	for i := range *count {
		role := ""
		switch i {
		case 0:
			role = "  <- moderator: has Delete buttons"
		case *count - 1:
			role = "  <- only connected to the node before it"
		}
		fmt.Printf("    node %d   http://127.0.0.1:%d/%s\n", i+1, *webBase+i, role)
	}
	fmt.Printf("\n  Post on one node and reload another: the post arrives through the peer-to-peer network.\n")
	fmt.Printf("  Data lives in %s; delete that folder to start over.\n\n", *dir)

	select {
	case <-ctx.Done():
		// Give every node a moment to shut down cleanly.
		for range *count {
			select {
			case <-errc:
			case <-time.After(5 * time.Second):
			}
		}
		return nil
	case err := <-errc:
		return err
	}
}

// prepareDemo creates keys, a signed manifest and node data directories the
// first time. It reports whether the directory was new.
func prepareDemo(dir string, count int) (bool, error) {
	manPath := filepath.Join(dir, "manifest.json")
	if _, err := os.Stat(manPath); err == nil {
		for i := range count {
			d := filepath.Join(dir, fmt.Sprintf("node%d", i+1))
			if _, err := os.Stat(filepath.Join(d, node.ManifestFile)); err != nil {
				if err := initQuiet(d, manPath); err != nil {
					return false, err
				}
			}
		}
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	maint, err := keys.LoadOrCreate(filepath.Join(dir, "maintainer.key"))
	if err != nil {
		return false, err
	}
	mod, err := keys.LoadOrCreate(filepath.Join(dir, "moderator.key"))
	if err != nil {
		return false, err
	}
	l := manifest.DefaultLimits
	l.PoWBits = 16 // lighter than the default so demo posting feels instant
	m := &manifest.Signed{Payload: manifest.Payload{
		Network: "demo", Seq: 1, Time: time.Now().Unix(), Threshold: 1,
		Maintainers: []keys.PublicKey{keys.Public(maint)},
		Moderators:  []keys.PublicKey{keys.Public(mod)},
		Boards: []manifest.Board{
			{ID: "linux", Title: "Linux & Free Software", Description: "Distros, desktops, kernels, configs."},
			{ID: "dev", Title: "Programming", Description: "Code, tools and languages."},
			{ID: "sec", Title: "Security & Privacy", Description: "Threat models, hardening, crypto."},
			{ID: "meta", Title: "Meta", Description: "About this network."},
		},
		Rules:  demoRules,
		Limits: l,
	}}
	m.Sign(maint)
	if err := os.WriteFile(manPath, m.Marshal(), 0o644); err != nil {
		return false, err
	}
	for i := range count {
		if err := initQuiet(filepath.Join(dir, fmt.Sprintf("node%d", i+1)), manPath); err != nil {
			return false, err
		}
	}
	return true, nil
}

func initQuiet(dir, manPath string) error {
	stdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = stdout }()
	return initDataDir(dir, manPath)
}

type seedPost struct {
	node    int // index into nodes
	poster  int // index into poster keys; same poster = same ID in a thread
	board   string
	subject string
	body    string
	image   string // label drawn on a generated image; "" for none
	reply   int    // index of the thread in the seed list, -1 for a new thread
	quote   int    // index of the post filled into a %s in body
	sage    bool
}

var seedPosts = []seedPost{
	{node: 0, poster: 0, board: "meta", subject: "Welcome to the network", image: "WELCOME", reply: -1,
		body: "This board has no server. Every member runs a node that keeps a full copy and serves it to the others.\n\n>posts are signed, so no host can edit them\n>images are re-encoded, so metadata never leaks\n>moderators delete by signing a tombstone that every node obeys\n\nRead the rules on the home page and say hi."},
	{node: 2, poster: 1, board: "meta", body: "Hi from node 3. I am only connected to node 2, so this reply hopped through it.", reply: 0},
	{node: 1, poster: 2, board: "meta", body: ">>%s\nWhat happens if node 2 goes offline?", reply: 0, quote: 1},
	{node: 0, poster: 0, board: "meta", body: ">>%s\nNode 3 keeps its own copy and keeps serving it. When the nodes see each other again they sync whatever they missed.", reply: 0, quote: 2},

	{node: 1, poster: 3, board: "linux", subject: "Post your desktop", image: "SWAY + FOOT", reply: -1,
		body: "Fresh Arch install. sway, foot, waybar, no bloat.\n>inb4 ricing is a waste of time"},
	{node: 2, poster: 4, board: "linux", image: "KDE PLASMA", body: "Plasma 6 on Debian testing. Works out of the box.", reply: 4},
	{node: 0, poster: 3, board: "linux", body: ">>%s\nClean. Post your dotfiles.", reply: 4, quote: 5},

	{node: 2, poster: 5, board: "linux", subject: "What distro are you running and why?", image: "DISTRO?", reply: -1,
		body: "Gentoo on the desktop, Alpine on servers. Compile times are a feature."},
	{node: 0, poster: 6, board: "linux", body: "Fedora. It just works and stays current.", reply: 7},
	{node: 1, poster: 7, board: "linux", body: "NixOS. Rolled back a broken update in ten seconds last week.", reply: 7, sage: true},

	{node: 0, poster: 8, board: "dev", subject: "Go vs Rust for networking code", image: "GO / RUST", reply: -1,
		body: "This network is written in Go with libp2p. Here is the whole post signing step:\n[code]\nsk := keys.ThreadKey(secret, threadSalt)\np.Author = keys.Public(sk)\np.Sig = ed25519.Sign(sk, p.unsigned())\n[/code]\nWould Rust have been worth it?"},
	{node: 2, poster: 9, board: "dev", body: "rust-libp2p is solid, but a single static Go binary is hard to beat for packaging.", reply: 10},

	{node: 1, poster: 10, board: "sec", subject: "Threat model thread", image: "THREAT MODEL", reply: -1,
		body: "What a malicious host can do here:\n>edit a post: rejected, signatures fail\n>replay an old manifest: rejected, sequence numbers only go up\n>serve a fake image: rejected, the hash does not match the CID\n\nWhat it can still do: refuse to relay. That is why every node keeps a full copy."},
	{node: 0, poster: 11, board: "sec", body: "[spoiler]Poster IDs change between threads, so you cannot follow someone across the board.[/spoiler]", reply: 12},
}

func seedDemo(ctx context.Context, nodes []*node.Node) error {
	// Wait until every node has joined the gossip mesh.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, n := range nodes {
			if n.PeerCount() == 0 {
				ok = false
			}
		}
		if ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	posters := make([]ed25519.PrivateKey, 12)
	for i := range posters {
		posters[i], _ = keys.Generate()
	}
	published := make([]*board.Post, len(seedPosts))
	start := time.Now().Add(-time.Duration(len(seedPosts)) * 3 * time.Minute)
	for i, sp := range seedPosts {
		n := nodes[min(sp.node, len(nodes)-1)]
		body := sp.body
		if strings.Contains(body, "%s") {
			body = fmt.Sprintf(body, board.ShortID(published[sp.quote].ID()))
		}
		p := &board.Post{Board: sp.board, Subject: sp.subject, Body: body, Sage: sp.sage,
			Time: start.Add(time.Duration(i) * 3 * time.Minute).Unix()}
		var salt []byte
		if sp.reply >= 0 {
			p.Thread = published[sp.reply].ID()
			salt = published[sp.reply].ThreadSalt
		}
		if sp.image != "" {
			res, err := media.Process(demoImage(sp.image, i), n.Manifest().Payload.Limits.MaxImageBytes)
			if err != nil {
				return err
			}
			full, err := n.Blobs.Put(res.Data)
			if err != nil {
				return err
			}
			thumb, err := n.Blobs.Put(res.Thumb)
			if err != nil {
				return err
			}
			p.Image = &board.ImageRef{CID: full, ThumbCID: thumb, Mime: res.Mime, Width: res.Width,
				Height: res.Height, Size: int64(len(res.Data)), Filename: fmt.Sprintf("demo-%02d.png", i)}
		}
		if err := p.Seal(posters[sp.poster], salt, n.Manifest().Payload.Limits.PoWBits); err != nil {
			return err
		}
		if err := n.PublishPost(ctx, p); err != nil {
			return fmt.Errorf("seed post %d: %w", i, err)
		}
		published[i] = p
		time.Sleep(150 * time.Millisecond)
	}
	return nil
}

// demoImage draws a simple poster-style PNG with a label.
func demoImage(label string, seed int) []byte {
	const w, h = 480, 320
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	hue := float64(seed*47%360) / 360
	for y := range h {
		for x := range w {
			t := float64(x+y) / float64(w+h)
			img.Set(x, y, hsv(hue+0.15*t, 0.55, 0.35+0.4*t))
		}
	}
	// A few circles so thumbnails are easy to tell apart.
	for k := range 5 {
		cx, cy := (seed*97+k*131)%w, (seed*53+k*89)%h
		r := 30 + (seed*13+k*17)%50
		c := hsv(hue+0.5+float64(k)*0.05, 0.4, 0.95)
		for y := max(0, cy-r); y < min(h, cy+r); y++ {
			for x := max(0, cx-r); x < min(w, cx+r); x++ {
				if (x-cx)*(x-cx)+(y-cy)*(y-cy) < r*r {
					img.Set(x, y, blend(img.RGBAAt(x, y), c, 0.35))
				}
			}
		}
	}
	// Draw the label small, then scale it up with hard pixels.
	face := basicfont.Face7x13
	tw := font.MeasureString(face, label).Ceil() + 4
	txt := image.NewRGBA(image.Rect(0, 0, tw, 16))
	d := &font.Drawer{Dst: txt, Src: image.NewUniform(color.White), Face: face, Dot: fixed.P(2, 12)}
	d.DrawString(label)
	scale := min(4, (w-40)/tw)
	dst := image.Rect(0, 0, tw*scale, 16*scale).Add(image.Pt((w-tw*scale)/2, (h-16*scale)/2))
	shadow := dst.Add(image.Pt(scale/2+1, scale/2+1))
	sh := image.NewRGBA(txt.Bounds())
	draw.DrawMask(sh, sh.Bounds(), image.NewUniform(color.RGBA{0, 0, 0, 160}), image.Point{}, txt, image.Point{}, draw.Src)
	xdraw.NearestNeighbor.Scale(img, shadow, sh, sh.Bounds(), xdraw.Over, nil)
	xdraw.NearestNeighbor.Scale(img, dst, txt, txt.Bounds(), xdraw.Over, nil)
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func blend(a color.RGBA, b color.RGBA, t float64) color.RGBA {
	mix := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t) }
	return color.RGBA{mix(a.R, b.R), mix(a.G, b.G), mix(a.B, b.B), 255}
}

func hsv(h, s, v float64) color.RGBA {
	h = math.Mod(h, 1) * 6
	i := math.Floor(h)
	f := h - i
	p, q, t := v*(1-s), v*(1-s*f), v*(1-s*(1-f))
	var r, g, b float64
	switch int(i) {
	case 0:
		r, g, b = v, t, p
	case 1:
		r, g, b = q, v, p
	case 2:
		r, g, b = p, v, t
	case 3:
		r, g, b = p, q, v
	case 4:
		r, g, b = t, p, v
	default:
		r, g, b = v, p, q
	}
	return color.RGBA{uint8(r * 255), uint8(g * 255), uint8(b * 255), 255}
}
