# Security

## Goals

1. A member who hosts the boards cannot change what other members see.
2. A host cannot impersonate a maintainer, a moderator or another poster.
3. Deleted content leaves every honest node.
4. The local web UI cannot be abused by other websites in the same browser.
5. A bug in the node should not expose the rest of the machine.

Public boards are readable by every member, including the people hosting
them. That is what "public" means. Private, encrypted boards are planned
(see Roadmap).

## Threats and defences

| Threat | Defence | Where |
|---|---|---|
| A peer edits a post in transit or at rest | Posts are ed25519-signed; ids are hashes of the canonical encoding | `board/post.go` |
| A peer serves a fake or altered image | Every blob is checked against its CID before it is stored or served | `blob/blob.go`, `node/blobs.go` |
| A forged manifest (new boards, new moderators) | Updates need a threshold of signatures from the current maintainers | `manifest/manifest.go` |
| Replay of an old manifest | Sequence numbers must strictly increase; the accepted manifest is stored on disk | `manifest.VerifyUpdate` |
| A fake moderator deletion | Tombstones must be signed by a key listed in the manifest | `board.Tombstone.Validate` |
| A deleted post comes back from a stale peer | Tombstones are stored permanently and synced before posts | `board/store.go`, `node/sync.go` |
| Spam floods | Proof of work per post; invalid messages are dropped and never forwarded | `board.Post.Seal`, `node/gossip.go` |
| Linking a poster across threads | Per-thread keys derived with HKDF; posts carry no libp2p author | `keys.ThreadKey`, `node/node.go` |
| Location data in photos | Images are decoded and re-encoded, dropping EXIF, XMP and comments | `media/media.go` |
| Polyglot files (image + HTML/JS) | Re-encoding keeps only pixel data; blobs are served with `nosniff` and a strict CSP | `media`, `web/server.go` |
| Decompression bombs | Dimensions are checked from the header before decoding | `media.Process` |
| XSS in post text | Text is HTML-escaped before markup; fuzz test checks that only known tags appear | `web/markup.go` |
| Other websites posting through your node (CSRF) | Per-process CSRF token on every form; the `Origin` header must be local, or `Sec-Fetch-Site` must be `same-origin` |  `web/server.go` |
| DNS rebinding | Requests with a `Host` header other than the loopback address are refused | `web/server.go` |
| Leaking your IP to sites linked in posts | URLs in posts are shown as text, not links; `Referrer-Policy: same-origin` sends no referrer to other sites | `web/markup.go` |
| Remote access to the web UI | The UI refuses to listen on anything but a loopback address | `web.New` |
| Resource exhaustion by peers | Connection manager, libp2p resource manager, frame and message size limits | `node` |
| Key theft from disk | Key files are created `0600` and refused if group- or world-readable | `keys.Load` |

## Known limitations

- **DHT eclipse (GO-2024-3218).** The Kademlia DHT can be eclipsed by an
  attacker who creates many node ids. There is no upstream fix. p2psite uses
  the DHT only to find peers, never for content. The peer cache, bootstrap
  list and mDNS keep working without it, and `-dht=false` turns it off.
- **Public discovery reveals IP addresses.** With `-public-discovery` on
  (the default), public DHT nodes that store or serve the rendezvous record
  learn which IP addresses advertise it. They cannot read posts or tell
  which network the key belongs to without the manifest. Anyone who has the
  manifest can find every member's address, which is also true of any
  member. Turn it off with `-public-discovery=false` and use bootstrap
  addresses for a closed network.
- **Gossip metadata.** The first peers to hear a post can guess which node
  sent it. Posts carry no node identity, but timing is visible to direct
  neighbours. p2psite is not an anonymity network.
- **Timestamps are claimed by the poster** and only bounded to at most five
  minutes in the future. A poster can backdate a post.
- **Moderation is trusted.** Any listed moderator can delete any post. Choose
  moderators carefully and rotate keys through a manifest update if one is
  lost.
- **No disk encryption.** Use full-disk encryption on the machine.

## Hardening the service

`packaging/p2psite.service` runs the node as an unprivileged user service
with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, a system-call
filter and write access limited to the data directory.

## Checks

```sh
make test     # includes race detector and HTTP security tests
make fuzz     # manifest, post and markup parsers
make vuln     # govulncheck
```

## Roadmap

- Private boards: per-board XChaCha20-Poly1305 keys wrapped to each member's
  X25519 key, so non-members store only ciphertext.
- Landlock rules applied by the binary itself.
- Reproducible, signed release builds.
- GossipSub peer scoring and per-peer rate limits on top of proof of work.
