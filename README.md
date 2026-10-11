# free-as-a-bird

A serverless, peer-to-peer imageboard for small communities.

Every member runs a node. Each node keeps a full copy of the boards and
serves it to the others, so there is no server to take down and no single
host to rotate. Posts are signed, images are content-addressed, and
moderators delete content by signing a tombstone that every node obeys.

The frontend is a deliberately plain, 4chan-style imageboard served by your
own node at `http://127.0.0.1:8088/`. It loads no third-party code and makes
no requests outside your node.

## Try it in one minute

Requires Go 1.27 or newer (see `go.mod`).

```sh
make demo        # or: go run ./cmd/free-as-a-bird demo
```

This starts three nodes in one process, connected in a line
(node 1 – node 2 – node 3), and fills them with sample threads:

| Node | URL                    | Notes                                     |
|------|------------------------|-------------------------------------------|
| 1    | http://127.0.0.1:8081/ | holds the moderator key: has Delete buttons |
| 2    | http://127.0.0.1:8082/ |                                           |
| 3    | http://127.0.0.1:8083/ | only connected to node 2                  |

Things to try:

- Post a thread on node 3, then reload node 1. It arrives through node 2.
- Reply on node 1 and watch the poster ID: it stays the same inside one
  thread but differs between threads.
- Delete a post on node 1. It disappears from all nodes, image included.
- Stop the demo (Ctrl+C) and start it again. Everything is still there.

Demo data lives in `./free-as-a-bird-demo`. Delete that folder to start over.

## Running a real network

### 1. Maintainers create the network once

```sh
free-as-a-bird keygen maintainer.key          # prints the maintainer public key
free-as-a-bird keygen moderator.key           # prints the moderator public key

free-as-a-bird manifest new -network linuxnet \
  -board 'linux:Linux & Free Software:Distros, desktops, kernels.' \
  -board 'dev:Programming' -board 'sec:Security & Privacy' -board 'meta:Meta' \
  -maintainer <MAINTAINER_PUBKEY> -moderator <MODERATOR_PUBKEY> \
  -bootstrap /ip4/<HUB_PUBLIC_IP>/udp/4001/quic-v1/p2p/<HUB_PEER_ID> \
  -rules-file rules.txt -out manifest.json

free-as-a-bird manifest sign -key maintainer.key manifest.json
free-as-a-bird manifest verify manifest.json
```

Share `manifest.json` with every member. Keep the `.key` files private.

With several maintainers, pass `-maintainer` once per key and set
`-threshold` (for example 2 of 3). Each maintainer runs `manifest sign`.

### 2. Every member

```sh
free-as-a-bird init -manifest manifest.json
free-as-a-bird serve
```

Then open http://127.0.0.1:8088/. No addresses are needed: nodes find each
other automatically (see "How members find each other" below). The first
contact usually takes under a minute.

### How members find each other

In order, a node tries:

1. members it has seen before (saved in `peers.json`);
2. bootstrap addresses from the manifest or `-bootstrap`;
3. mDNS: members on the same LAN find each other instantly;
4. the network's own DHT;
5. **public discovery**: the public IPFS DHT as a meeting point. Members
   advertise under a key derived from the manifest, so only people with the
   manifest can look it up. Public libp2p nodes act as short-lived relays so
   that two members behind home NAT can punch a direct connection.

Public discovery is on by default. It reveals your IP address to public DHT
nodes (not what you post) and uses about 30 MB more memory. For a closed
network, run `serve -public-discovery=false` and give everyone a bootstrap
address instead.

Direct connections can still fail behind symmetric NAT, common on mobile
and some ISP-level NAT. Then you need a hub, or a VPN such as Tailscale.

### 3. Hub nodes (optional, recommended)

Members behind home NAT connect to each other directly when hole punching
works. When it does not, they still get every post through a hub: a hub is a
normal node with a public address, so everyone can connect to it directly and
it passes posts and images on like any other member. Its relay only helps
two NAT'd members punch a direct connection; it never carries their traffic.

```sh
free-as-a-bird serve -hub -port 4001
```

Its address appears on the node status page (`/status`). Add hub addresses
to the manifest's bootstrap list. Members also remember the peers they have
seen, so the network keeps working even if every hub goes away.

### Updating the manifest

```sh
free-as-a-bird manifest bump manifest.json      # edit the file, then:
free-as-a-bird manifest sign -key maintainer.key manifest.json
free-as-a-bird serve -publish-manifest manifest.json
```

The update spreads to every node. Nodes accept it only with a higher
sequence number and a threshold of signatures from the current maintainers.

### Moderating

```sh
free-as-a-bird serve -mod-key moderator.key
```

Delete buttons appear next to each post. A deletion is a signed tombstone:
every node removes the post (or the whole thread, for an opener) and its
image, refuses to store it again, and passes the tombstone on to nodes that
were offline.

## Commands

```
free-as-a-bird demo     [-dir DIR] [-nodes N]       run N local nodes with sample content
free-as-a-bird keygen   FILE                        create a signing key, print its public key
free-as-a-bird manifest new|sign|bump|verify        create and sign the network manifest
free-as-a-bird init     -manifest FILE [-data DIR]  set up a node data directory
free-as-a-bird serve    [flags]                     run a node and the local web UI
```

Useful `serve` flags: `-web 127.0.0.1:8088`, `-port 4001`, `-hub`,
`-bootstrap ADDR`, `-mdns=false`, `-dht=false`, `-public-discovery=false`,
`-mod-key FILE`, `-v`.
The default data directory is `~/.local/share/free-as-a-bird`.

## Development

```sh
make test        # unit and integration tests with the race detector
make fuzz        # fuzz the parsers for 30 s each
make build       # ./bin/free-as-a-bird
```

Documentation:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how nodes find each other,
  replicate posts and fetch images
- [docs/SECURITY.md](docs/SECURITY.md): threat model and what each defence
  covers
