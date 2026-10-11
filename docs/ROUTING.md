# Routing

p2psite's own multi-hop routing layer. It lets a visitor reach a land's
service, and a land reach the network, without either side's node learning
the other's IP address. It is built directly on libp2p streams. It is not
Tor and borrows no Tor code; it reuses the circuit/onion idea, which is
public cryptography, and implements it in `internal/route`.

This layer is **opt-in per land** (`anonymous: true`). A land that does not
ask for it is reached over a plain libp2p connection, which is faster and
hides the visitor's identity but not their IP. `SECURITY.md` states exactly
what each mode hides.

## Why we build our own instead of a one-hop proxy

A single relay hides the visitor's IP from the destination, but the relay
itself sees both ends. That is no better than a VPN. Hiding an address from
the other party *and* from the machines in the middle needs at least two
relays chosen so that no single relay sees both ends. That is onion routing,
and there is no shortcut to it.

## Pieces we already have

| Need | Reuse |
|---|---|
| Per-node long-term key | libp2p `node.key` (ed25519) |
| Open a stream to a peer | `host.NewStream`, protocol `/p2psite/<net>/route/1.0.0` |
| List of online relays | `node.Members()` (peers speaking our sync protocol) |
| Key derivation | HKDF-SHA256, as in `keys.ThreadKey` |
| Spam cost | proof of work, as on posts |

## Keys

Every node already has an ed25519 identity. For circuit crypto we need an
X25519 key for Diffie-Hellman. We derive it from the node key with HKDF so
no new key file is needed, and publish the X25519 public key in the peer's
network record:

    x25519_priv = HKDF(node_ed25519_seed, "", "p2psite/route-dh/v1", 32)

ed25519 and X25519 use the same curve but we never reuse the signing key as
a DH key directly: separate derivation, separate purpose.

## Cells

Everything on a circuit is a fixed-size **cell** so that length never
correlates one hop with the next. One size, `CellSize = 512` bytes:

    [ 2  ] command        (CREATE, CREATED, RELAY, DESTROY)
    [ 16 ] circuit id      (per hop, rewritten at each relay)
    [ .. ] body, zero-padded to CellSize

A `RELAY` body is itself onion-wrapped and, once fully peeled, holds a
stream frame for the land's service (length-prefixed, padded).

## Circuit construction (telescoping)

The visitor builds the circuit one hop at a time so each relay only ever
learns its predecessor and successor, never the whole path.

1. Visitor picks a path of `Hops` relays from `Members()` (default 2 relays
   + the destination). It excludes itself and, where it can tell, the
   destination's own node.
2. **Hop 1.** Visitor opens a `route` stream to relay R1 and sends `CREATE`
   with an ephemeral X25519 public key. R1 completes the handshake
   (`x25519(R1_priv, eph_pub)` → HKDF → a forward and a backward ChaCha20
   key) and replies `CREATED` with its own ephemeral public key. Visitor now
   shares keys `k1` with R1.
3. **Hop 2.** Visitor sends R1 a `RELAY` cell whose body, encrypted under
   `k1`, says "extend to R2". R1 opens a `route` stream to R2 and relays a
   `CREATE` on the visitor's behalf. The `CREATED` comes back wrapped; the
   visitor now shares `k2` with R2. R1 never sees `k2`.
4. Repeat for every hop. Each added hop costs one round trip.

A data cell is encrypted once per hop in reverse order (k2 then k1); each
relay peels one layer and forwards. Replies are encrypted forward (k1 then
k2) and peeled by the visitor.

## Reaching a land without revealing the land's IP

If the last relay simply dialed the land, that relay would learn the land's
address. So the land stays behind its own circuit and the two meet at a
**rendezvous** relay — the same construction Tor hidden services use, built
by us:

1. The land keeps circuits open to a few **introduction** relays and
   publishes, in its signed land record (see `LANDS.md`), which relays those
   are and its route public key.
2. A visitor picks a rendezvous relay R, builds a circuit to it, and tells R
   a one-time rendezvous cookie.
3. The visitor sends the land, through an introduction relay, "meet me at R
   with this cookie", signed so only this land's record key is trusted.
4. The land builds its own circuit to R and presents the cookie. R splices
   the two circuits: from then on it forwards cells blindly between them.
5. Neither R nor any relay sees both IPs: the visitor built its half, the
   land built its half, R sees only two circuits.

A land that does not care about hiding its own IP (a public hub, say) can
skip rendezvous and publish a direct route address instead; then the last
relay dials it. The land record says which mode it uses.

## The visitor's virtual IP

The service behind a land (`127.0.0.1:3000`) still wants to tell its visitors
apart — to rate-limit, to ban. The circuit carries no IP, so the land's node
derives a stable virtual address per (visitor, land) pair and passes it to
the local service as a `Forwarded: for="[...]"` header, from the ULA range
`fd00::/8`:

    vip = fd00::/8 prefix || HKDF(land_secret, visitor_route_pubkey,
                                  "p2psite/visitor-vip/v1", 16)[...]

The visitor proves ownership of `visitor_route_pubkey` by signing the
rendezvous cookie. So the same visitor is stable within one land, and two
different lands derive unlinkable addresses for the same visitor.

New keys are free, so a banned visitor can mint a fresh one. The land raises
the cost with proof of work on first contact; the land picks the difficulty.

## What this hides, and what it does not

Honest limits, repeated in `SECURITY.md`:

- **Anonymity set is small.** Maybe 10–20 members are online at once. An
  adversary who runs several relays, or who watches the whole network, can
  use packet timing and volume to link the two ends of a circuit. Fixed-size
  cells and padding raise the cost but do not defeat a global observer on a
  network this size.
- **Sybil.** Anyone holding the manifest can spawn many nodes and raise the
  chance of owning both the first and the last relay on a circuit. Defences,
  in order of how soon we add them: pin a small set of long-lived **guard**
  relays as the first hop so a visitor is not re-exposed on every circuit;
  weight path selection away from brand-new peers; require proof of work to
  be listed as a relay.
- **This layer protects IP addresses, not the machine's operator.** The node
  that runs a circuit still knows its own traffic. The virtual IP hides the
  visitor from the *land's application*, not from the person running the
  land's node, and only the rendezvous mode hides the land from the
  visitor's node.
- **Latency.** Two hops add two round trips to connect and encrypt every
  cell twice. Fine for browsing a site, slow for a chatty API. This is why
  it is opt-in per land, and why heavy lands should run their own group's
  nodes rather than leaning on volunteers' relays.

## Build order

1. `internal/route`: X25519 derivation, cell format, onion wrap/unwrap, the
   handshake. Pure functions with fuzz tests, no networking.
2. The `route` stream handler and telescoping circuit builder in
   `internal/node`, with a loopback two-relay test.
3. Rendezvous: introduction relays, cookies, splicing.
4. Wire it to lands: `anonymous: true`, the land record's route key, the
   `*.freeasabird.localhost` front end dialing through a circuit.
5. Guard relays and relay proof of work.
