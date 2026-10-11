# Architecture

## Overview

```
 browser ──HTTP (loopback only)──▶ web ──▶ node ──libp2p──▶ other nodes
                                    │        │
                                    ▼        ▼
                               board.Store  blob.Store
                               (bbolt)      (files named by CID)
```

| Package             | Responsibility                                                  |
|---------------------|-----------------------------------------------------------------|
| `internal/manifest` | Signed network manifest: boards, maintainers, moderators, limits |
| `internal/keys`     | ed25519 keys, on-disk format, per-thread poster keys             |
| `internal/board`    | Posts, tombstones, validation, thread store, bump and prune      |
| `internal/blob`     | Content-addressed image store (CIDv1, raw, sha2-256)             |
| `internal/media`    | Image re-encoding, metadata stripping, thumbnails                |
| `internal/route`    | Onion-routing crypto: X25519 derivation, ntor handshake, cells  |
| `internal/node`     | libp2p host, discovery, GossipSub, sync and blob protocols       |
| `internal/web`      | Imageboard HTML frontend                                         |
| `cmd/p2psite`       | CLI and the local demo                                          |

## Replication model

Every node stores every live post and image. There is no designated host.
Load spreads across whoever is online, and losing any node loses nothing.

Storage stays bounded because boards behave like a classic imageboard: each
board keeps `threads_per_page × pages` threads (150 by default) in bump
order. A thread that falls off the last page is deleted on every node, and
its id is remembered for 30 days so slow peers cannot bring it back.

The bump order is a pure function of the posts a node holds, so two nodes
with the same posts prune the same threads.

## Identities

| Key                 | Held by        | Used for                                    |
|---------------------|----------------|---------------------------------------------|
| Maintainer key      | maintainers    | signing manifests (k of n)                  |
| Moderator key       | moderators     | signing tombstones                          |
| Poster secret       | every member   | deriving one signing key per thread         |
| Node key            | every node     | libp2p transport identity only              |

A poster's key for a thread is `HKDF(poster secret, thread salt)`. The same
member keeps one poster ID inside a thread, but their posts in different
threads cannot be linked. Posts are gossiped without a libp2p author field,
so a post is never tagged with the node that wrote it.

## Data formats

All signed objects are canonical JSON: the receiver re-encodes the parsed
value and rejects it if the bytes differ. This gives every post one id
everywhere.

- **Post id**: base32 sha-256 of the encoded post (52 characters). The UI
  shows the first 10.
- **Image id**: CIDv1 (raw codec, sha2-256), the same ids IPFS uses.
- **Proof of work**: the leading zero bits of sha-256 over the unsigned post
  must reach `limits.pow_bits` (20 by default, about a second on a laptop).

## Network protocols

All protocol ids and topics include the network name, so separate networks
never mix.

| Name                                 | Kind          | Purpose                           |
|--------------------------------------|---------------|-----------------------------------|
| `/p2psite/<net>/v1/board/<id>`       | GossipSub     | new posts                         |
| `/p2psite/<net>/v1/tombstones`       | GossipSub     | moderator deletions               |
| `/p2psite/<net>/v1/manifest`         | GossipSub     | manifest updates                  |
| `/p2psite/<net>/sync/1.0.0`          | stream        | catch-up after being offline      |
| `/p2psite/<net>/blob/1.0.0`          | stream        | fetch one image by CID            |
| `/p2psite/<net>/kad/1.0.0`           | Kademlia DHT  | find peers of this network        |

GossipSub validators do the real work. A node stores a post before
forwarding it, and only after every check passes. Invalid messages are
dropped and never forwarded.

### Sync

When two nodes connect, and every two minutes with a few random peers, a node:

1. asks for the peer's manifest and applies it if it is a valid update;
2. fetches tombstones it does not have, so it never downloads deleted posts;
3. compares per-thread digests (a hash of the sorted post ids) for each
   board, and fetches only the threads that differ.

### Images

After a post is accepted, its thumbnail and image are queued for download.
The node asks the peer it heard the post from first, then other peers. Every
download is checked against its CID. Failed downloads are retried after 2, 5,
15 and 45 seconds, and a repair pass every two minutes picks up anything
still missing. Nodes only serve blobs that a live post references.

## Peer discovery

In order of preference:

1. **Peer cache**: addresses of recently connected members, saved in
   `peers.json`.
2. **Bootstrap list**: from the manifest and `-bootstrap` flags.
3. **mDNS**: members on the same LAN find each other with no configuration.
4. **Network DHT**: a private Kademlia DHT (`/p2psite/<net>` prefix).
5. **Public discovery** (`-public-discovery`, on by default): the node joins
   the public IPFS (Amino) DHT in client mode and advertises a provider record
   under a rendezvous key, then looks the key up to find other members.

The rendezvous key is `sha256("p2psite/rendezvous/v1\n" + network + "\n" +
manifest.rendezvous)`. `manifest new` fills `rendezvous` with 16 random
bytes, so the key cannot be guessed from the network name. The public DHT
stores only a hash of it.

Members are told apart from public DHT peers by checking whether they speak
`/p2psite/<net>/sync/1.0.0`. Member connections are protected from the
connection manager, and the UI counts only members.

### NAT traversal

Nodes that find themselves behind NAT use AutoRelay to reserve a slot on a
relay: hub nodes from the bootstrap list first, then public libp2p nodes
from the public DHT routing table. A peer that wants to reach a NAT'd member
connects through the relay, and DCUtR then upgrades the connection to a
direct one by hole punching.

Relays, hubs included, only carry this handshake. They keep libp2p's default
Circuit Relay v2 limits (2 minutes, 128 KiB per connection), and a node never
syncs or fetches blobs over a relayed connection: such a stream would block
until hole punching succeeds. So no relay, public or hub, carries member
traffic, and a heavy user cannot drain a shared hub through it.

Hole punching fails behind symmetric NAT. Those members still reach every
post through a hub: a hub is a full member with a public address, so NAT'd
members connect to it directly and it stores and forwards posts and images
like any other node. A VPN works too.

## Resource limits

- Connection manager: 16 low / 48 high watermark, or 32 / 96 with public
  discovery. Memory is about 45 MB per node without public discovery and
  about 75 MB with it.
- libp2p resource manager with default scaled limits.
- Post size 64 KiB, image size from the manifest (2 MiB by default),
  decoded images at most 10000×10000 and 40 megapixels.
- bbolt for posts, one file per image blob.
