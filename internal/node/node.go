// Package node runs the peer-to-peer side of free-as-a-bird: the libp2p host,
// peer discovery, GossipSub for new posts, and the sync and blob protocols
// that let nodes catch up after being offline.
package node

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"

	"github.com/randwardatake/free-as-a-bird/internal/blob"
	"github.com/randwardatake/free-as-a-bird/internal/board"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
	"github.com/randwardatake/free-as-a-bird/internal/route"
)

// Config controls how a node joins the network.
type Config struct {
	DataDir string
	// ListenAddrs are libp2p multiaddrs; empty means TCP and QUIC on Port.
	ListenAddrs []string
	Port        int
	// Hub nodes are publicly reachable: they relay for NAT'd peers and run
	// the DHT in server mode.
	Hub       bool
	Bootstrap []string
	MDNS      bool
	DHT       bool
	// PublicDiscovery uses the public IPFS DHT as a meeting point and public
	// libp2p nodes as temporary relays, so members find each other with no
	// configured addresses. It reveals member IP addresses to public DHT
	// nodes; turn it off for a closed network.
	PublicDiscovery bool
	LowConns        int
	HighConns       int
	Logger          *slog.Logger
}

// Node is a running free-as-a-bird peer.
type Node struct {
	cfg    Config
	log    *slog.Logger
	host   host.Host
	ps     *pubsub.PubSub
	dht    *dht.IpfsDHT
	pubDHT atomic.Pointer[dht.IpfsDHT]
	Store  *board.Store
	Blobs  *blob.Store
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	man     atomic.Pointer[manifest.Signed]
	manMu   sync.Mutex
	topicMu sync.Mutex
	topics  map[string]*pubsub.Topic

	fetch     chan fetchReq
	inflight  sync.Map // cid -> struct{}
	lastSync  sync.Map // peer.ID -> time.Time
	connected atomic.Int64

	// routeKey is this node's static X25519 key for the onion-routing
	// handshake, derived from the node key. RouteHandler, if set, answers a
	// circuit's data cells at the exit hop; nil means echo.
	routeKey     *ecdh.PrivateKey
	RouteHandler func([]byte) []byte
	// rendez maps a one-time rendezvous cookie to the meeting point two
	// circuits are spliced at when this node is their rendezvous relay.
	rendez sync.Map
	// intro maps a land's introduction key to a function that delivers an
	// INTRODUCE payload down the land's circuit, when this node is an
	// introduction point for that land.
	intro sync.Map
}

// Paths inside the data directory.
const (
	ManifestFile = "manifest.json"
	nodeKeyFile  = "node.key"
	dbFile       = "board.db"
	blobDir      = "blobs"
	peersFile    = "peers.json"
)

func (n *Node) proto(name string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/free-as-a-bird/%s/%s/1.0.0", n.Manifest().Payload.Network, name))
}

func (n *Node) topicName(name string) string {
	return fmt.Sprintf("/free-as-a-bird/%s/v1/%s", n.Manifest().Payload.Network, name)
}

// LoadManifest reads the trusted manifest from a data directory.
func LoadManifest(dataDir string) (*manifest.Signed, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, ManifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no manifest in %s: run `free-as-a-bird init` first", dataDir)
		}
		return nil, err
	}
	m, err := manifest.Parse(b)
	if err != nil {
		return nil, err
	}
	if err := m.VerifyGenesis(); err != nil {
		return nil, fmt.Errorf("stored manifest: %w", err)
	}
	return m, nil
}

func loadNodeKey(path string) (crypto.PrivKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		sk, _, err := crypto.GenerateEd25519Key(nil)
		if err != nil {
			return nil, err
		}
		raw, err := crypto.MarshalPrivateKey(sk)
		if err != nil {
			return nil, err
		}
		return sk, os.WriteFile(path, raw, 0o600)
	}
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPrivateKey(b)
}

// New starts a node. Stop it with Close.
func New(cfg Config) (*Node, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.LowConns == 0 {
		cfg.LowConns, cfg.HighConns = 16, 48
		if cfg.PublicDiscovery {
			// Public DHT queries open short-lived connections to many
			// nodes; member connections are protected from trimming.
			cfg.LowConns, cfg.HighConns = 32, 96
		}
	}
	m, err := LoadManifest(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, log: cfg.Logger, topics: map[string]*pubsub.Topic{}, fetch: make(chan fetchReq, 4096)}
	n.man.Store(m)
	n.ctx, n.cancel = context.WithCancel(context.Background())

	ok := false
	defer func() {
		if !ok {
			n.Close()
		}
	}()

	if n.Store, err = board.Open(filepath.Join(cfg.DataDir, dbFile), &m.Payload); err != nil {
		return nil, err
	}
	if n.Blobs, err = blob.Open(filepath.Join(cfg.DataDir, blobDir)); err != nil {
		return nil, err
	}
	if err := n.startHost(); err != nil {
		return nil, err
	}
	if err := n.startPubSub(); err != nil {
		return nil, err
	}
	n.host.SetStreamHandler(n.proto("sync"), n.handleSync)
	n.host.SetStreamHandler(n.proto("blob"), n.handleBlob)
	n.host.SetStreamHandler(n.proto("route"), n.handleRoute)
	n.host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			n.connected.Add(1)
			go n.maybeSync(c.RemotePeer())
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			n.connected.Add(-1)
			if n.host.Network().Connectedness(c.RemotePeer()) != network.Connected {
				n.host.ConnManager().Unprotect(c.RemotePeer(), memberTag)
			}
		},
	})
	for range 3 {
		n.goLoop(n.fetchWorker)
	}
	n.goLoop(n.maintainLoop)
	if err := n.startDiscovery(); err != nil {
		return nil, err
	}
	ok = true
	n.log.Info("node started", "peer", n.host.ID(), "network", m.Payload.Network, "addrs", n.Addrs())
	return n, nil
}

func (n *Node) goLoop(f func()) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		f()
	}()
}

func (n *Node) startHost() error {
	sk, err := loadNodeKey(filepath.Join(n.cfg.DataDir, nodeKeyFile))
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	raw, err := sk.Raw()
	if err != nil || len(raw) < 32 {
		return fmt.Errorf("node key: cannot derive route key: %w", err)
	}
	if n.routeKey, err = route.DHKeyFromSeed(raw[:32]); err != nil {
		return fmt.Errorf("route key: %w", err)
	}
	cm, err := connmgr.NewConnManager(n.cfg.LowConns, n.cfg.HighConns, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return err
	}
	listen := n.cfg.ListenAddrs
	if len(listen) == 0 {
		listen = []string{
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", n.cfg.Port),
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", n.cfg.Port),
			fmt.Sprintf("/ip6/::/tcp/%d", n.cfg.Port),
			fmt.Sprintf("/ip6/::/udp/%d/quic-v1", n.cfg.Port),
		}
	}
	opts := []libp2p.Option{
		libp2p.Identity(sk),
		libp2p.ListenAddrStrings(listen...),
		libp2p.ConnectionManager(cm),
		libp2p.UserAgent("free-as-a-bird/0.1"),
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
	}
	if n.cfg.Hub {
		// A hub is a full member with a public address: NAT'd members
		// exchange posts with it directly. Its relay keeps libp2p's small
		// default limits on purpose. It only carries the hole-punching
		// handshake between two NAT'd members, never their traffic, so
		// heavy users cannot drain a shared hub. The relay service starts
		// only on public reachability, which the operator asserts with -hub
		// instead of waiting for AutoNAT.
		opts = append(opts, libp2p.EnableRelayService(), libp2p.EnableNATService(),
			libp2p.ForceReachabilityPublic())
	} else {
		// When we turn out to be behind NAT, reserve a slot on a relay so
		// that peers can reach us and upgrade to a direct connection with
		// hole punching. Candidates are our hubs first, then public nodes.
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(n.relayCandidates,
			autorelay.WithBootDelay(10*time.Second), autorelay.WithMinCandidates(2)))
	}
	n.host, err = libp2p.New(opts...)
	return err
}

func (n *Node) startPubSub() error {
	var err error
	n.ps, err = pubsub.NewGossipSub(n.ctx, n.host,
		// Posts and tombstones carry their own signatures. Leaving pubsub
		// messages unsigned and authorless means a post is never tied to
		// the peer ID of the node that wrote it.
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithNoAuthor(),
		pubsub.WithMessageIdFn(func(m *pb.Message) string {
			h := sha256.Sum256(m.Data)
			return string(h[:])
		}),
		pubsub.WithMaxMessageSize(board.MaxPostSize+4096),
		pubsub.WithPeerExchange(n.cfg.Hub),
	)
	if err != nil {
		return err
	}
	return n.joinTopics()
}

// Host exposes the libp2p host (used by tests and the status page).
func (n *Node) Host() host.Host { return n.host }

// Manifest returns the currently trusted manifest.
func (n *Node) Manifest() *manifest.Signed { return n.man.Load() }

// Addrs returns this node's full multiaddrs including the peer ID.
func (n *Node) Addrs() []string {
	var out []string
	for _, a := range n.host.Addrs() {
		out = append(out, fmt.Sprintf("%s/p2p/%s", a, n.host.ID()))
	}
	return out
}

// PeerCount returns the number of connected members of this network.
func (n *Node) PeerCount() int { return len(n.Members()) }

// AcceptManifest verifies a manifest update and, if valid, stores it,
// applies it and gossips it. It returns manifest.ErrNotNewer for stale ones.
func (n *Node) AcceptManifest(raw []byte) error {
	next, err := manifest.Parse(raw)
	if err != nil {
		return err
	}
	n.manMu.Lock()
	defer n.manMu.Unlock()
	if err := manifest.VerifyUpdate(n.Manifest(), next); err != nil {
		return err
	}
	path := filepath.Join(n.cfg.DataDir, ManifestFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, next.Marshal(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	n.man.Store(next)
	n.Store.SetManifest(&next.Payload)
	n.log.Info("accepted manifest update", "seq", next.Payload.Seq)
	return n.joinTopics()
}

// Connect dials a peer by multiaddr (used by tests and the CLI).
func (n *Node) Connect(ctx context.Context, addr string) error {
	ai, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return err
	}
	return n.host.Connect(ctx, *ai)
}

// Close stops the node.
func (n *Node) Close() error {
	if n.host != nil {
		n.savePeerCache()
	}
	n.cancel()
	if n.dht != nil {
		n.dht.Close()
	}
	if pub := n.pubDHT.Load(); pub != nil {
		pub.Close()
	}
	if n.host != nil {
		n.host.Close()
	}
	n.wg.Wait()
	if n.Store != nil {
		n.Store.Close()
	}
	return nil
}
