package land

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
)

// MaxRecordSize is the largest encoded registration a node will parse.
const MaxRecordSize = 16 << 10

// MaxIntro is the most introduction points a route descriptor may list.
const MaxIntro = 8

const signingDomain = "free-as-a-bird/land-record/v1\n"

// labelRe matches one DNS label, since a land is served at
// <name>.<group>.localhost.
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// RoutePub is an X25519 public key that marshals to unpadded base64url,
// like keys.PublicKey.
type RoutePub []byte

func (k RoutePub) String() string { return base64.RawURLEncoding.EncodeToString(k) }

func (k RoutePub) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *RoutePub) UnmarshalText(b []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("route key: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("route key: want 32 bytes, got %d", len(raw))
	}
	*k = raw
	return nil
}

// Equal reports whether two keys are byte-identical.
func (k RoutePub) Equal(o RoutePub) bool { return string(k) == string(o) }

// ECDH returns the key in the form internal/route takes.
func (k RoutePub) ECDH() (*ecdh.PublicKey, error) { return ecdh.X25519().NewPublicKey(k) }

// RoutePubOf returns the public half of a route key from Master.RouteKey.
func RoutePubOf(k *ecdh.PrivateKey) RoutePub { return RoutePub(k.PublicKey().Bytes()) }

// Route is the route descriptor: how a visitor reaches the land.
type Route struct {
	RoutePub RoutePub `json:"route_pub"`
	// Anonymous lands are reachable only through a rendezvous circuit and
	// list the relays they keep introduction circuits to in Intro.
	Anonymous bool `json:"anonymous"`
	// Intro holds libp2p peer IDs of introduction relays.
	Intro   []string `json:"intro,omitempty"`
	PoWBits int      `json:"pow_bits"`
}

// Payload is the signed content of a land registration.
type Payload struct {
	Network string         `json:"network"`
	Name    string         `json:"name"`
	Group   string         `json:"group"`
	Seq     uint64         `json:"seq"`
	Time    int64          `json:"time"`
	Land    keys.PublicKey `json:"land"`
	Route   Route          `json:"route"`
}

// Record is a registration plus its signatures: the land key's own and a
// threshold of maintainers', as stored and transmitted.
type Record struct {
	Payload    Payload              `json:"payload"`
	Signatures []manifest.Signature `json:"signatures"`
}

// Host is the land's address within the network, "<name>.<group>".
func (p *Payload) Host() string { return p.Name + "." + p.Group }

// SigningBytes is the exact byte string the land key and maintainers sign.
func (p *Payload) SigningBytes() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // Payload contains only marshalable types
	}
	return append([]byte(signingDomain), b...)
}

// Validate checks that the payload is internally consistent.
func (p *Payload) Validate() error {
	if !labelRe.MatchString(p.Name) {
		return fmt.Errorf("name %q: use 1-32 chars of a-z, 0-9 and inner '-'", p.Name)
	}
	if !labelRe.MatchString(p.Group) {
		return fmt.Errorf("group %q: use 1-32 chars of a-z, 0-9 and inner '-'", p.Group)
	}
	if p.Seq == 0 {
		return errors.New("seq must be at least 1")
	}
	if len(p.Land) != ed25519.PublicKeySize {
		return errors.New("land key: bad length")
	}
	return p.Route.Validate()
}

// Validate checks the route descriptor.
func (r *Route) Validate() error {
	if _, err := r.RoutePub.ECDH(); err != nil {
		return fmt.Errorf("route_pub: %w", err)
	}
	if r.PoWBits < 0 || r.PoWBits > 32 {
		return errors.New("pow_bits must be 0-32")
	}
	if !r.Anonymous {
		if len(r.Intro) != 0 {
			return errors.New("intro points are only used when anonymous")
		}
		return nil
	}
	if len(r.Intro) == 0 || len(r.Intro) > MaxIntro {
		return fmt.Errorf("an anonymous land needs 1-%d intro points", MaxIntro)
	}
	seen := map[peer.ID]bool{}
	for _, s := range r.Intro {
		id, err := peer.Decode(s)
		if err != nil {
			return fmt.Errorf("intro %q: %w", s, err)
		}
		if id.String() != s {
			return fmt.Errorf("intro %q: not in canonical form", s)
		}
		if seen[id] {
			return fmt.Errorf("intro %s is listed twice", s)
		}
		seen[id] = true
	}
	return nil
}

// Sign adds (or replaces) the signature of sk and drops signatures that no
// longer match the payload, e.g. after the payload was edited. The land owner
// signs with Master.LandKey; maintainers sign with their own keys.
func (r *Record) Sign(sk ed25519.PrivateKey) {
	msg := r.Payload.SigningBytes()
	pub := keys.Public(sk)
	kept := r.Signatures[:0]
	for _, sig := range r.Signatures {
		if sig.Key.Equal(pub) || !ed25519.Verify(ed25519.PublicKey(sig.Key), msg, sig.Sig) {
			continue
		}
		kept = append(kept, sig)
	}
	r.Signatures = append(kept, manifest.Signature{Key: pub, Sig: ed25519.Sign(sk, msg)})
}

// signedBy reports whether k has a valid signature over the payload.
func (r *Record) signedBy(msg []byte, k keys.PublicKey) bool {
	for _, sig := range r.Signatures {
		if len(k) == ed25519.PublicKeySize && sig.Key.Equal(k) && ed25519.Verify(ed25519.PublicKey(k), msg, sig.Sig) {
			return true
		}
	}
	return false
}

// countValid returns how many distinct keys from signers have a valid
// signature over the payload.
func (r *Record) countValid(msg []byte, signers []keys.PublicKey) int {
	counted := map[string]bool{}
	for _, k := range signers {
		if !counted[string(k)] && r.signedBy(msg, k) {
			counted[string(k)] = true
		}
	}
	return len(counted)
}

// Verify checks a registration against the manifest the node currently
// trusts: it must be valid, for that network, signed by its own land key,
// and signed by a threshold of the manifest's maintainers.
func (r *Record) Verify(m *manifest.Payload) error {
	if r.Payload.Network != m.Network {
		return fmt.Errorf("land record is for network %q, not %q", r.Payload.Network, m.Network)
	}
	if err := r.Payload.Validate(); err != nil {
		return err
	}
	msg := r.Payload.SigningBytes()
	if !r.signedBy(msg, r.Payload.Land) {
		return errors.New("land record is not signed by its land key")
	}
	if n := r.countValid(msg, m.Maintainers); n < m.Threshold {
		return fmt.Errorf("land record has %d valid maintainer signatures, needs %d", n, m.Threshold)
	}
	return nil
}

// ErrNotNewer is returned by VerifyUpdate for a record whose sequence number
// is not above the current one. Callers usually ignore it silently.
var ErrNotNewer = errors.New("land record is not newer than the current one")

// VerifyUpdate checks that next may replace cur for the same name. Besides
// passing Verify, a record that moves the name to a different land key must
// also be signed by the current land key, so a name can only be rotated by
// its owner.
func VerifyUpdate(m *manifest.Payload, cur, next *Record) error {
	if next.Payload.Name != cur.Payload.Name || next.Payload.Group != cur.Payload.Group {
		return fmt.Errorf("land record is for %q, not %q", next.Payload.Host(), cur.Payload.Host())
	}
	if next.Payload.Seq <= cur.Payload.Seq {
		return ErrNotNewer
	}
	if err := next.Verify(m); err != nil {
		return err
	}
	if !next.Payload.Land.Equal(cur.Payload.Land) && !next.signedBy(next.Payload.SigningBytes(), cur.Payload.Land) {
		return errors.New("land key rotation is not signed by the current land key")
	}
	return nil
}

// Parse decodes a land record strictly and validates its payload, so every
// record it returns marshals back to a parseable form. It does not verify
// signatures.
func Parse(b []byte) (*Record, error) {
	if len(b) > MaxRecordSize {
		return nil, errors.New("land record too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("land record: %w", err)
	}
	if dec.More() {
		return nil, errors.New("land record: trailing data")
	}
	if err := r.Payload.Validate(); err != nil {
		return nil, fmt.Errorf("land record: %w", err)
	}
	for _, sig := range r.Signatures {
		if len(sig.Key) != ed25519.PublicKeySize || len(sig.Sig) != ed25519.SignatureSize {
			return nil, errors.New("land record: malformed signature")
		}
	}
	return &r, nil
}

// Marshal encodes the record for storage or transmission.
func (r *Record) Marshal() []byte {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}
