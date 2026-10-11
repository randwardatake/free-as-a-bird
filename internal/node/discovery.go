package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	ma "github.com/multiformats/go-multiaddr"
)

// Peer discovery, from most to least private:
//
//  1. the peer cache: members this node has seen before;
//  2. bootstrap addresses from the manifest and the -bootstrap flag;
//  3. mDNS on the local network;
//  4. the network's own DHT (needs one of the above to join);
//  5. the public IPFS DHT as a meeting point, so that two members with no
//     configured addresses still find each other.

// memberTag protects connections to members from the connection manager,
// which would otherwise trim them in favour of public DHT peers.
const memberTag = "p2psite-member"

// rendezvous is the key members advertise under. It is derived from the
// manifest, so only people holding the manifest can look it up, and the
// public DHT only ever sees its hash.
func (n *Node) rendezvous() string {
	p := n.Manifest().Payload
	h := sha256.Sum256([]byte("p2psite/rendezvous/v1\n" + p.Network + "\n" + p.Rendezvous))
	return "p2psite/" + hex.EncodeToString(h[:16])
}

func (n *Node) isMember(p peer.ID) bool {
	protos, err := n.host.Peerstore().SupportsProtocols(p, n.proto("sync"))
	return err == nil && len(protos) > 0
}

// Members lists connected peers that belong to this network.
func (n *Node) Members() []peer.ID {
	var out []peer.ID
	for _, p := range n.host.Network().Peers() {
		if n.isMember(p) {
			out = append(out, p)
		}
	}
	return out
}

// direct reports whether we have a connection to p that is not relayed.
// A stream over a relayed (limited) connection blocks until hole punching
// yields a direct one, which may never happen, so posts and blobs are only
// exchanged with peers we reach directly.
func (n *Node) direct(p peer.ID) bool {
	for _, c := range n.host.Network().ConnsToPeer(p) {
		if !c.Stat().Limited {
			return true
		}
	}
	return false
}

// dataPeers lists members we can sync with and fetch blobs from now.
func (n *Node) dataPeers() []peer.ID {
	var out []peer.ID
	for _, p := range n.Members() {
		if n.direct(p) {
			out = append(out, p)
		}
	}
	return out
}

// AllPeerCount counts every connection, including public DHT peers.
func (n *Node) AllPeerCount() int { return len(n.host.Network().Peers()) }

func (n *Node) bootstrapPeers() []peer.AddrInfo {
	var out []peer.AddrInfo
	seen := map[peer.ID]bool{}
	addrs := append(append([]string{}, n.cfg.Bootstrap...), n.Manifest().Payload.Bootstrap...)
	for _, s := range addrs {
		ai, err := peer.AddrInfoFromString(s)
		if err != nil {
			n.log.Warn("bad bootstrap address", "addr", s, "err", err)
			continue
		}
		if !seen[ai.ID] && ai.ID != n.host.ID() {
			seen[ai.ID] = true
			out = append(out, *ai)
		}
	}
	return out
}

type mdnsNotifee struct{ n *Node }

func (m mdnsNotifee) HandlePeerFound(ai peer.AddrInfo) {
	if ai.ID == m.n.host.ID() {
		return
	}
	go m.n.connect(ai)
}

func (n *Node) connect(ai peer.AddrInfo) {
	if ai.ID == n.host.ID() || n.host.Network().Connectedness(ai.ID) == network.Connected {
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	defer cancel()
	if err := n.host.Connect(ctx, ai); err != nil {
		n.log.Debug("connect failed", "peer", ai.ID, "err", err)
	}
}

func (n *Node) startDiscovery() error {
	for _, ai := range n.loadPeerCache() {
		go n.connect(ai)
	}
	for _, ai := range n.bootstrapPeers() {
		n.host.Peerstore().AddAddrs(ai.ID, ai.Addrs, peerstore.PermanentAddrTTL)
		go n.connect(ai)
	}
	if n.cfg.MDNS {
		svc := mdns.NewMdnsService(n.host, "p2psite-"+n.Manifest().Payload.Network, mdnsNotifee{n})
		if err := svc.Start(); err != nil {
			n.log.Warn("mDNS unavailable", "err", err)
		}
	}
	var finders []*drouting.RoutingDiscovery
	if n.cfg.DHT {
		mode := dht.ModeAuto
		if n.cfg.Hub {
			mode = dht.ModeServer
		}
		var err error
		n.dht, err = dht.New(n.host,
			dht.ProtocolPrefix(protocol.ID("/p2psite/"+n.Manifest().Payload.Network)),
			dht.Mode(mode),
			dht.BootstrapPeers(n.bootstrapPeers()...),
		)
		if err != nil {
			return fmt.Errorf("dht: %w", err)
		}
		if err := n.dht.Bootstrap(n.ctx); err != nil {
			return fmt.Errorf("dht bootstrap: %w", err)
		}
		finders = append(finders, drouting.NewRoutingDiscovery(n.dht))
	}
	if n.cfg.PublicDiscovery {
		boot := dht.GetDefaultBootstrapPeerAddrInfos()
		pub, err := dht.New(n.host, dht.Mode(dht.ModeClient), dht.BootstrapPeers(boot...))
		if err != nil {
			return fmt.Errorf("public dht: %w", err)
		}
		n.pubDHT.Store(pub)
		for _, ai := range boot {
			go n.connect(ai)
		}
		if err := pub.Bootstrap(n.ctx); err != nil {
			return fmt.Errorf("public dht bootstrap: %w", err)
		}
		finders = append(finders, drouting.NewRoutingDiscovery(pub))
	}
	for _, f := range finders {
		n.goLoop(func() { n.advertiseLoop(f) })
	}
	if len(finders) > 0 {
		n.goLoop(func() { n.findLoop(finders) })
	}
	return nil
}

// advertiseLoop keeps our rendezvous record alive. Unlike the libp2p helper
// it retries quickly while the DHT routing table is still filling up, so a
// new member becomes findable within seconds rather than minutes.
func (n *Node) advertiseLoop(rd *drouting.RoutingDiscovery) {
	wait := 3 * time.Second
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(wait):
		}
		ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
		ttl, err := rd.Advertise(ctx, n.rendezvous())
		cancel()
		if err != nil {
			n.log.Debug("advertise failed, retrying", "err", err)
			wait = 15 * time.Second
			continue
		}
		wait = ttl * 7 / 8
	}
}

// findLoop looks up other members: often while we know few of them, rarely
// once we are well connected.
func (n *Node) findLoop(finders []*drouting.RoutingDiscovery) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		if len(n.Members()) < 8 {
			for _, rd := range finders {
				n.findVia(rd)
			}
		}
		switch m := len(n.Members()); {
		case m == 0:
			t.Reset(15 * time.Second)
		case m < 4:
			t.Reset(30 * time.Second)
		default:
			t.Reset(5 * time.Minute)
		}
	}
}

func (n *Node) findVia(rd *drouting.RoutingDiscovery) {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	ch, err := rd.FindPeers(ctx, n.rendezvous())
	if err != nil {
		return
	}
	for ai := range ch {
		if ai.ID == n.host.ID() || n.host.Network().Connectedness(ai.ID) == network.Connected {
			continue
		}
		n.log.Debug("discovered member", "peer", ai.ID)
		go n.connect(ai)
	}
}

// relayCandidates feeds AutoRelay: our own hubs first, then public nodes
// from the public DHT routing table. Public relays only carry the short
// handshake that lets two NAT'd members punch a direct connection.
func (n *Node) relayCandidates(ctx context.Context, num int) <-chan peer.AddrInfo {
	out := make(chan peer.AddrInfo, num)
	go func() {
		defer close(out)
		sent := 0
		send := func(ai peer.AddrInfo) bool {
			if sent >= num || len(ai.Addrs) == 0 || ai.ID == n.host.ID() {
				return sent < num
			}
			select {
			case out <- ai:
				sent++
			case <-ctx.Done():
				return false
			}
			return sent < num
		}
		for _, ai := range n.bootstrapPeers() {
			if !send(ai) {
				return
			}
		}
		pub := n.pubDHT.Load()
		if pub == nil {
			return
		}
		peers := pub.RoutingTable().ListPeers()
		rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		for _, p := range peers {
			if !send(peer.AddrInfo{ID: p, Addrs: n.host.Peerstore().Addrs(p)}) {
				return
			}
		}
	}()
	return out
}

// maintainLoop periodically syncs with random members, repairs missing
// blobs, expires old state and saves the peer cache.
func (n *Node) maintainLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		members := n.Members()
		peers := n.dataPeers()
		rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		for _, p := range peers[:min(3, len(peers))] {
			go n.syncWith(p)
		}
		n.repairBlobs()
		if freed, err := n.Store.Maintain(time.Now()); err == nil {
			n.freeBlobs(freed)
		}
		if len(members) == 0 {
			for _, ai := range append(n.bootstrapPeers(), n.loadPeerCache()...) {
				go n.connect(ai)
			}
		}
		n.savePeerCache()
	}
}

type cachedPeer struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

// savePeerCache stores addresses of connected members so the node can
// rejoin the network even when every bootstrap node is gone.
func (n *Node) savePeerCache() {
	var out []cachedPeer
	for _, p := range n.Members() {
		cp := cachedPeer{ID: p.String()}
		for _, a := range n.host.Peerstore().Addrs(p) {
			cp.Addrs = append(cp.Addrs, a.String())
		}
		if len(cp.Addrs) > 0 {
			out = append(out, cp)
		}
		if len(out) >= 50 {
			break
		}
	}
	if len(out) == 0 {
		return
	}
	b, _ := json.Marshal(out)
	path := filepath.Join(n.cfg.DataDir, peersFile)
	if err := os.WriteFile(path+".tmp", b, 0o600); err == nil {
		os.Rename(path+".tmp", path)
	}
}

func (n *Node) loadPeerCache() []peer.AddrInfo {
	b, err := os.ReadFile(filepath.Join(n.cfg.DataDir, peersFile))
	if err != nil {
		return nil
	}
	var cps []cachedPeer
	if json.Unmarshal(b, &cps) != nil {
		return nil
	}
	var out []peer.AddrInfo
	for _, cp := range cps {
		id, err := peer.Decode(cp.ID)
		if err != nil || id == n.host.ID() {
			continue
		}
		ai := peer.AddrInfo{ID: id}
		for _, s := range cp.Addrs {
			if a, err := ma.NewMultiaddr(s); err == nil {
				ai.Addrs = append(ai.Addrs, a)
			}
		}
		out = append(out, ai)
	}
	return out
}
