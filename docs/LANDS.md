# Lands

A **land** is one person's own site or API inside free-as-a-bird: their corner of the
network, addressed by a name like `randward.freeasabird`. Joining a node does
not require a land — a member can just seed other people's posts and lands.
Anyone who wants one claims a name and hosts a service behind it.

This document covers land identity: the keys, the backup phrase, the signed
name registry, and the per-visitor virtual IP. How a visitor's traffic reaches
a land without exposing either side's IP is in `ROUTING.md`.

## Keys

A land is owned by a key, not by a person or a node. Everything is derived on
the owner's own device from one randomly generated **master secret**, so the
land key is never tied to the node key, the poster secret, or an IP address.

    land_secret  = HKDF(master_secret, "", "free-as-a-bird/land/v1", 32)   -> ed25519
    land_onion   = HKDF(master_secret, "", "free-as-a-bird/land-route/v1", 32) -> X25519

The land key signs the land's records. The route key is the land's static
X25519 key for the `ROUTING.md` handshake; it is derived separately so one key
never serves two cryptographic purposes.

The master secret is the single point of control: **whoever holds it owns the
land, and losing it loses the land.** There is no recovery path by design — no
server holds a copy. So the owner must back it up.

## Backup phrase

On first creation the node shows a 24-word phrase (BIP-39 wordlist, 256 bits)
that encodes the master secret. The owner writes it down offline. Entering the
phrase on another device re-derives every land key identically. Nothing else
needs to be copied.

12 words (128 bits) is offered as a shorter option; 24 is the default because a
lost land cannot be reissued.

## The name registry

Names (`randward`, `freeasabird` as a suffix group) map to land keys in a
registry that the network's maintainers sign, reusing the manifest machinery:

- A registration binds a **name** to a **land public key** and a **route
  descriptor** (see below). It carries no information identifying the person.
- Registrations are signed by a threshold of the current maintainers, exactly
  like manifest updates (`manifest/manifest.go`), so a host cannot forge a name
  or redirect someone else's.
- Sequence numbers strictly increase; the newest signed record wins, so a name
  can be rotated to a new key by its owner with a maintainer co-signature.
- The registry syncs over its own GossipSub topic and is served during sync,
  like tombstones.

A name resolves locally: the browser asks the node, the node looks the name up
in its copy of the registry, and gets the land's key and route descriptor. No
external DNS is involved.

## Route descriptor

Each registration includes how to reach the land, signed by the land key:

| Field | Meaning |
|---|---|
| `route_pub` | the land's static X25519 key (`ROUTING.md` handshake) |
| `anonymous` | `true`: reachable only through a rendezvous circuit; `false`: a direct route address is published and the last relay dials it |
| `intro` | when `anonymous`, the relays the land keeps introduction circuits to |
| `pow_bits` | first-contact proof-of-work difficulty the land requires of visitors |

`anonymous: false` is faster and fine for a public hub that does not mind
revealing its own IP. `anonymous: true` keeps the land's IP hidden too, at the
cost of latency. The choice is the land owner's, per land.

## Serving

A land points at a local service — a static directory the node serves, or the
owner's own program on `127.0.0.1:3000`. The node is a reverse proxy in front
of it:

    randward.freeasabird.localhost:8088
      -> node resolves the name in the registry
      -> (ROUTING.md) a circuit to the land's node
      -> land node proxies to its local service

Each land gets its own browser origin (`<name>.<group>.localhost`), so one
land's page cannot read another's cookies or storage. `.localhost` names are a
secure context, so service workers and `crypto.subtle` work with no certificate
and no local root CA — which a compromised node could abuse to read all HTTPS.

## The visitor's virtual IP

The service behind a land still wants to tell visitors apart — to rate-limit,
to ban — but a circuit carries no IP. So the land node derives a stable virtual
address per `(visitor, land)` pair and passes it to the local service as a
`Forwarded: for="[...]"` header, from the ULA range `fd00::/8`:

    vip = fd00::/8 || HKDF(land_secret, visitor_route_pub,
                          "free-as-a-bird/visitor-vip/v1", ...)

The visitor proves ownership of `visitor_route_pub` during the circuit
handshake. So the same visitor is stable within one land, while two different
lands derive unlinkable virtual IPs for the same visitor.

This hides the visitor from the land's **application**, not from the person
running the land's node — stated plainly, as in `SECURITY.md`. A banned visitor
can mint a fresh key for free; the land raises the cost with `pow_bits` on first
contact.

## Quotas and hosting

A land costs storage and relaying. Public nodes stay healthy only if heavy
lands carry their own weight:

- A land on a shared public node gets a bounded quota.
- Over quota, the owner hosts it with their own group — pairing their friends'
  peers as seeders, or running their group's nodes. The public node is never
  drained for one tenant.
- Unbounded resources exist only as an explicit opt-in on a group-owned node.

## Build order

1. `internal/land`: master secret, 24-word phrase, `land_secret` / `land_onion`
   derivation, signed registration and route descriptor. Pure, tested.
2. Registry sync: a GossipSub topic and sync step, mirroring tombstones.
3. Name resolution and the `<name>.<group>.localhost` reverse proxy in
   `internal/web`.
4. Wire to routing: the descriptor's `route_pub` / `anonymous`, dialing a land
   through a circuit, and the virtual-IP header.
5. Quotas on the public node.
