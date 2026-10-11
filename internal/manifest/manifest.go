// Package manifest defines the signed network manifest: the list of boards,
// maintainers, moderators and limits that every node agrees on.
//
// A node is initialised with a genesis manifest that must be signed by a
// threshold of its own maintainers. Later manifests are accepted only when
// they carry a strictly higher sequence number and are signed by a threshold
// of the maintainers listed in the manifest the node currently trusts.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
)

// MaxSize is the largest encoded manifest a node will parse.
const MaxSize = 256 << 10

const signingDomain = "free-as-a-bird/manifest/v1\n"

var (
	networkRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	boardRe   = regexp.MustCompile(`^[a-z0-9]{1,10}$`)
)

// reserved are first path segments the web UI uses itself.
var reserved = map[string]bool{"": true, "static": true, "blob": true, "status": true, "mod": true, "api": true}

// ReservedPath reports whether a first URL path segment belongs to the web
// UI rather than to a board.
func ReservedPath(seg string) bool { return reserved[seg] }

// Board is one imageboard section, such as /linux/.
type Board struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// Limits are the network-wide rules every node enforces on posts.
type Limits struct {
	PoWBits         int   `json:"pow_bits"`
	MaxImageBytes   int64 `json:"max_image_bytes"`
	MaxBodyChars    int   `json:"max_body_chars"`
	BumpLimit       int   `json:"bump_limit"`
	ThreadsPerPage  int   `json:"threads_per_page"`
	Pages           int   `json:"pages"`
	OPImageRequired bool  `json:"op_image_required"`
}

// DefaultLimits are used by `free-as-a-bird manifest new`.
var DefaultLimits = Limits{
	PoWBits:         20,
	MaxImageBytes:   2 << 20,
	MaxBodyChars:    4000,
	BumpLimit:       300,
	ThreadsPerPage:  15,
	Pages:           10,
	OPImageRequired: true,
}

// MaxThreads is the number of live threads a board keeps before pruning.
func (l Limits) MaxThreads() int { return l.ThreadsPerPage * l.Pages }

// Payload is the signed content of a manifest.
type Payload struct {
	Network     string           `json:"network"`
	Seq         uint64           `json:"seq"`
	Time        int64            `json:"time"`
	Threshold   int              `json:"threshold"`
	Maintainers []keys.PublicKey `json:"maintainers"`
	Moderators  []keys.PublicKey `json:"moderators"`
	Boards      []Board          `json:"boards"`
	Rules       string           `json:"rules,omitempty"`
	Bootstrap   []string         `json:"bootstrap,omitempty"`
	// Rendezvous is a random string mixed into the key members advertise
	// under on the public DHT. Only manifest holders can compute that key.
	Rendezvous string `json:"rendezvous,omitempty"`
	Limits     Limits `json:"limits"`
}

// Signature is one maintainer's signature over a payload.
type Signature struct {
	Key keys.PublicKey `json:"key"`
	Sig []byte         `json:"sig"`
}

// Signed is a payload plus maintainer signatures, as stored and transmitted.
type Signed struct {
	Payload    Payload     `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// SigningBytes is the exact byte string maintainers sign.
func (p *Payload) SigningBytes() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // Payload contains only marshalable types
	}
	return append([]byte(signingDomain), b...)
}

// Validate checks that the payload is internally consistent.
func (p *Payload) Validate() error {
	if !networkRe.MatchString(p.Network) {
		return fmt.Errorf("network %q: use 1-32 chars of a-z, 0-9 and '-'", p.Network)
	}
	if len(p.Maintainers) == 0 {
		return errors.New("at least one maintainer is required")
	}
	if p.Threshold < 1 || p.Threshold > len(p.Maintainers) {
		return fmt.Errorf("threshold %d must be between 1 and %d", p.Threshold, len(p.Maintainers))
	}
	if err := uniqueKeys(p.Maintainers); err != nil {
		return fmt.Errorf("maintainers: %w", err)
	}
	if err := uniqueKeys(p.Moderators); err != nil {
		return fmt.Errorf("moderators: %w", err)
	}
	if len(p.Rendezvous) > 64 {
		return errors.New("rendezvous must be at most 64 bytes")
	}
	if len(p.Boards) == 0 || len(p.Boards) > 64 {
		return errors.New("between 1 and 64 boards are required")
	}
	seen := map[string]bool{}
	for _, b := range p.Boards {
		if !boardRe.MatchString(b.ID) {
			return fmt.Errorf("board id %q: use 1-10 chars of a-z and 0-9", b.ID)
		}
		if reserved[b.ID] {
			return fmt.Errorf("board id %q is reserved", b.ID)
		}
		if seen[b.ID] {
			return fmt.Errorf("board id %q is listed twice", b.ID)
		}
		seen[b.ID] = true
		if b.Title == "" || len(b.Title) > 64 {
			return fmt.Errorf("board %q: title must be 1-64 bytes", b.ID)
		}
	}
	l := p.Limits
	switch {
	case l.PoWBits < 0 || l.PoWBits > 32:
		return errors.New("limits.pow_bits must be 0-32")
	case l.MaxImageBytes < 1<<10 || l.MaxImageBytes > 16<<20:
		return errors.New("limits.max_image_bytes must be 1 KiB-16 MiB")
	case l.MaxBodyChars < 1 || l.MaxBodyChars > 20000:
		return errors.New("limits.max_body_chars must be 1-20000")
	case l.BumpLimit < 1 || l.BumpLimit > 1000:
		return errors.New("limits.bump_limit must be 1-1000")
	case l.ThreadsPerPage < 1 || l.ThreadsPerPage > 50, l.Pages < 1 || l.Pages > 50:
		return errors.New("limits.threads_per_page and limits.pages must be 1-50")
	}
	return nil
}

func uniqueKeys(ks []keys.PublicKey) error {
	seen := map[string]bool{}
	for _, k := range ks {
		if len(k) != ed25519.PublicKeySize {
			return errors.New("bad key length")
		}
		if seen[string(k)] {
			return fmt.Errorf("key %s is listed twice", k)
		}
		seen[string(k)] = true
	}
	return nil
}

// Sign adds (or replaces) the signature of sk and drops signatures that no
// longer match the payload, e.g. after the payload was edited.
func (s *Signed) Sign(sk ed25519.PrivateKey) {
	msg := s.Payload.SigningBytes()
	pub := keys.Public(sk)
	kept := s.Signatures[:0]
	for _, sig := range s.Signatures {
		if sig.Key.Equal(pub) || !ed25519.Verify(ed25519.PublicKey(sig.Key), msg, sig.Sig) {
			continue
		}
		kept = append(kept, sig)
	}
	s.Signatures = append(kept, Signature{Key: pub, Sig: ed25519.Sign(sk, msg)})
}

// countValid returns how many distinct keys from signers have a valid
// signature over the payload.
func (s *Signed) countValid(signers []keys.PublicKey) int {
	msg := s.Payload.SigningBytes()
	allowed := map[string]bool{}
	for _, k := range signers {
		allowed[string(k)] = true
	}
	counted := map[string]bool{}
	for _, sig := range s.Signatures {
		k := string(sig.Key)
		if !allowed[k] || counted[k] {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(sig.Key), msg, sig.Sig) {
			counted[k] = true
		}
	}
	return len(counted)
}

// VerifyGenesis checks a manifest used as a node's initial trust root: it
// must be valid and signed by a threshold of its own maintainers.
func (s *Signed) VerifyGenesis() error {
	if err := s.Payload.Validate(); err != nil {
		return err
	}
	if n := s.countValid(s.Payload.Maintainers); n < s.Payload.Threshold {
		return fmt.Errorf("manifest has %d valid maintainer signatures, needs %d", n, s.Payload.Threshold)
	}
	return nil
}

// ErrNotNewer is returned by VerifyUpdate for a manifest whose sequence
// number is not above the current one. Callers usually ignore it silently.
var ErrNotNewer = errors.New("manifest is not newer than the current one")

// VerifyUpdate checks that next may replace cur.
func VerifyUpdate(cur, next *Signed) error {
	if next.Payload.Network != cur.Payload.Network {
		return fmt.Errorf("manifest is for network %q, not %q", next.Payload.Network, cur.Payload.Network)
	}
	if next.Payload.Seq <= cur.Payload.Seq {
		return ErrNotNewer
	}
	if n := next.countValid(cur.Payload.Maintainers); n < cur.Payload.Threshold {
		return fmt.Errorf("update has %d valid signatures from current maintainers, needs %d", n, cur.Payload.Threshold)
	}
	// The new maintainer set must also be able to sign its own manifest,
	// otherwise the network could lock itself out of future updates.
	return next.VerifyGenesis()
}

// Parse decodes a manifest strictly. It does not verify signatures.
func Parse(b []byte) (*Signed, error) {
	if len(b) > MaxSize {
		return nil, errors.New("manifest too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Signed
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: trailing data")
	}
	return &s, nil
}

// Marshal encodes the manifest for storage or transmission.
func (s *Signed) Marshal() []byte {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// Board returns the board with the given id.
func (p *Payload) Board(id string) (Board, bool) {
	for _, b := range p.Boards {
		if b.ID == id {
			return b, true
		}
	}
	return Board{}, false
}

// IsModerator reports whether k may sign tombstones.
func (p *Payload) IsModerator(k keys.PublicKey) bool {
	for _, m := range p.Moderators {
		if m.Equal(k) {
			return true
		}
	}
	return false
}
