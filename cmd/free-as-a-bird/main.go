// Command free-as-a-bird runs a node of a serverless, peer-to-peer imageboard.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
	"github.com/randwardatake/free-as-a-bird/internal/node"
	"github.com/randwardatake/free-as-a-bird/internal/web"
)

const version = "0.1.0"

const usage = `free-as-a-bird - a serverless peer-to-peer imageboard

Usage:
  free-as-a-bird demo     [-dir DIR] [-nodes N]       run N local nodes with sample content
  free-as-a-bird keygen   FILE                        create a signing key, print its public key
  free-as-a-bird manifest new    [flags] -out FILE    write an unsigned manifest
  free-as-a-bird manifest sign   -key FILE  MANIFEST  add a maintainer signature
  free-as-a-bird manifest bump   MANIFEST             raise the sequence number for an update
  free-as-a-bird manifest verify MANIFEST             check a manifest's signatures
  free-as-a-bird init     -manifest FILE [-data DIR]  set up a node data directory
  free-as-a-bird serve    [flags]                     run a node and the local web UI
  free-as-a-bird version

Run "free-as-a-bird <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "demo":
		err = cmdDemo(args)
	case "keygen":
		err = cmdKeygen(args)
	case "manifest":
		err = cmdManifest(args)
	case "init":
		err = cmdInit(args)
	case "serve":
		err = cmdServe(args)
	case "version", "-v", "--version":
		fmt.Println("free-as-a-bird", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "free-as-a-bird")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "free-as-a-bird-data"
	}
	return filepath.Join(home, ".local", "share", "free-as-a-bird")
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func cmdKeygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: free-as-a-bird keygen FILE")
	}
	sk, err := keys.Generate()
	if err != nil {
		return err
	}
	if err := keys.Save(args[0], sk); err != nil {
		return err
	}
	fmt.Printf("wrote %s\npublic key: %s\n", args[0], keys.Public(sk))
	return nil
}

func cmdManifest(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: free-as-a-bird manifest new|sign|bump|verify ...")
	}
	switch args[0] {
	case "new":
		return manifestNew(args[1:])
	case "sign":
		return manifestSign(args[1:])
	case "bump":
		return manifestBump(args[1:])
	case "verify":
		return manifestVerify(args[1:])
	}
	return fmt.Errorf("unknown manifest command %q", args[0])
}

func manifestNew(args []string) error {
	fs := flag.NewFlagSet("manifest new", flag.ExitOnError)
	network := fs.String("network", "", "network name, e.g. linuxnet (required)")
	threshold := fs.Int("threshold", 1, "maintainer signatures needed for updates")
	rules := fs.String("rules-file", "", "text file with the network rules")
	pow := fs.Int("pow-bits", manifest.DefaultLimits.PoWBits, "proof-of-work difficulty per post")
	out := fs.String("out", "", "output file (required)")
	var boards, maint, mods, boot multiFlag
	fs.Var(&boards, "board", `board as "id:Title[:Description]" (repeatable, required)`)
	fs.Var(&maint, "maintainer", "maintainer public key (repeatable, required)")
	fs.Var(&mods, "moderator", "moderator public key (repeatable)")
	fs.Var(&boot, "bootstrap", "bootstrap multiaddr (repeatable)")
	fs.Parse(args)
	if *network == "" || *out == "" || len(boards) == 0 || len(maint) == 0 {
		fs.Usage()
		return errors.New("-network, -out, -board and -maintainer are required")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	p := manifest.Payload{Network: *network, Seq: 1, Time: time.Now().Unix(), Threshold: *threshold,
		Bootstrap: boot, Rendezvous: hex.EncodeToString(salt), Limits: manifest.DefaultLimits}
	p.Limits.PoWBits = *pow
	for _, b := range boards {
		parts := strings.SplitN(b, ":", 3)
		if len(parts) < 2 {
			return fmt.Errorf("board %q: use id:Title[:Description]", b)
		}
		bd := manifest.Board{ID: parts[0], Title: parts[1]}
		if len(parts) == 3 {
			bd.Description = parts[2]
		}
		p.Boards = append(p.Boards, bd)
	}
	for _, s := range maint {
		k, err := keys.ParsePublicKey(s)
		if err != nil {
			return err
		}
		p.Maintainers = append(p.Maintainers, k)
	}
	for _, s := range mods {
		k, err := keys.ParsePublicKey(s)
		if err != nil {
			return err
		}
		p.Moderators = append(p.Moderators, k)
	}
	if *rules != "" {
		b, err := os.ReadFile(*rules)
		if err != nil {
			return err
		}
		p.Rules = strings.TrimSpace(string(b))
	}
	if err := p.Validate(); err != nil {
		return err
	}
	s := &manifest.Signed{Payload: p}
	if err := os.WriteFile(*out, s.Marshal(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (unsigned). Next: free-as-a-bird manifest sign -key MAINTAINER.key %s\n", *out, *out)
	return nil
}

func readManifest(path string) (*manifest.Signed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return manifest.Parse(b)
}

func manifestSign(args []string) error {
	fs := flag.NewFlagSet("manifest sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "maintainer key file (required)")
	fs.Parse(args)
	if *keyFile == "" || fs.NArg() != 1 {
		return errors.New("usage: free-as-a-bird manifest sign -key FILE MANIFEST")
	}
	sk, err := keys.Load(*keyFile)
	if err != nil {
		return err
	}
	m, err := readManifest(fs.Arg(0))
	if err != nil {
		return err
	}
	m.Sign(sk)
	if err := os.WriteFile(fs.Arg(0), m.Marshal(), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s as %s (%d signature(s), threshold %d)\n", fs.Arg(0), keys.Public(sk), len(m.Signatures), m.Payload.Threshold)
	return nil
}

func manifestBump(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: free-as-a-bird manifest bump MANIFEST")
	}
	m, err := readManifest(args[0])
	if err != nil {
		return err
	}
	m.Payload.Seq++
	m.Payload.Time = time.Now().Unix()
	m.Signatures = nil
	if err := os.WriteFile(args[0], m.Marshal(), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s is now sequence %d. Signatures were cleared; ask the maintainers to sign again.\n", args[0], m.Payload.Seq)
	return nil
}

func manifestVerify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: free-as-a-bird manifest verify MANIFEST")
	}
	m, err := readManifest(args[0])
	if err != nil {
		return err
	}
	if err := m.VerifyGenesis(); err != nil {
		return err
	}
	fmt.Printf("ok: network %s, sequence %d, %d board(s), %d maintainer(s), threshold %d\n",
		m.Payload.Network, m.Payload.Seq, len(m.Payload.Boards), len(m.Payload.Maintainers), m.Payload.Threshold)
	return nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	mf := fs.String("manifest", "", "signed network manifest (required)")
	data := fs.String("data", defaultDataDir(), "data directory")
	fs.Parse(args)
	if *mf == "" {
		return errors.New("usage: free-as-a-bird init -manifest FILE [-data DIR]")
	}
	return initDataDir(*data, *mf)
}

func initDataDir(dir, manifestPath string) error {
	m, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := m.VerifyGenesis(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, node.ManifestFile)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists; this data directory is already initialised", dst)
	}
	if err := os.WriteFile(dst, m.Marshal(), 0o600); err != nil {
		return err
	}
	if _, err := keys.LoadOrCreate(filepath.Join(dir, "poster.key")); err != nil {
		return err
	}
	fmt.Printf("initialised %s for network %s\n", dir, m.Payload.Network)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	webAddr := fs.String("web", "127.0.0.1:8088", "loopback address for the web UI")
	port := fs.Int("port", 4001, "TCP and UDP port for peer connections (0 = random)")
	hub := fs.Bool("hub", false, "act as a hub: relay for NAT'd peers and serve the DHT (needs a public address)")
	mdns := fs.Bool("mdns", true, "find peers on the local network")
	useDHT := fs.Bool("dht", true, "find peers through the network's DHT")
	public := fs.Bool("public-discovery", true, "find members through the public IPFS DHT and public relays (reveals your IP to public DHT nodes)")
	modKey := fs.String("mod-key", "", "moderator key file; enables delete buttons")
	publish := fs.String("publish-manifest", "", "signed manifest update to apply and gossip on start")
	verbose := fs.Bool("v", false, "verbose logging")
	var boot multiFlag
	fs.Var(&boot, "bootstrap", "extra bootstrap multiaddr (repeatable)")
	fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runNode(ctx, log, nodeOpts{
		data: *data, web: *webAddr, port: *port, hub: *hub, mdns: *mdns, dht: *useDHT, public: *public,
		modKey: *modKey, publish: *publish, bootstrap: boot,
	})
}

type nodeOpts struct {
	data, web       string
	port            int
	hub, mdns, dht  bool
	public          bool
	modKey, publish string
	bootstrap       []string
	listen          []string
	ready           chan<- *node.Node
}

func runNode(ctx context.Context, log *slog.Logger, o nodeOpts) error {
	poster, err := keys.LoadOrCreate(filepath.Join(o.data, "poster.key"))
	if err != nil {
		return fmt.Errorf("poster key: %w", err)
	}
	n, err := node.New(node.Config{
		DataDir: o.data, Port: o.port, ListenAddrs: o.listen, Hub: o.hub, MDNS: o.mdns, DHT: o.dht,
		PublicDiscovery: o.public,
		Bootstrap:       o.bootstrap, Logger: log,
	})
	if err != nil {
		return err
	}
	defer n.Close()
	if o.publish != "" {
		raw, err := os.ReadFile(o.publish)
		if err != nil {
			return err
		}
		if err := n.PublishManifest(ctx, raw); err != nil && !errors.Is(err, manifest.ErrNotNewer) {
			return fmt.Errorf("publish manifest: %w", err)
		}
	}
	cfg := web.Config{Addr: o.web, PosterKey: poster, Logger: log}
	if o.modKey != "" {
		if cfg.ModKey, err = keys.Load(o.modKey); err != nil {
			return fmt.Errorf("moderator key: %w", err)
		}
	}
	srv, err := web.New(n, cfg)
	if err != nil {
		return err
	}
	ln, err := web.Listen(o.web)
	if err != nil {
		return fmt.Errorf("web UI: %w (pick another address with -web)", err)
	}
	if o.ready != nil {
		o.ready <- n
	}
	log.Info("web UI ready", "url", "http://"+o.web+"/")
	return srv.Serve(ctx, ln)
}
