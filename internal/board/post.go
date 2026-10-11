// Package board implements the imageboard data model: signed posts,
// moderator tombstones, validation rules, and the local thread store.
package board

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
)

const (
	postDomain      = "free-as-a-bird/post/v1\n"
	tombstoneDomain = "free-as-a-bird/tombstone/v1\n"

	// MaxPostSize bounds an encoded post on the wire.
	MaxPostSize = 64 << 10
	// MaxClockSkew is how far in the future a post's timestamp may be.
	MaxClockSkew = 5 * time.Minute
	// MaxReason bounds a tombstone's reason in bytes of UTF-8.
	MaxReason = 200

	maxSubject = 100
	maxName    = 50
	maxFile    = 120
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ImageRef points at an image blob and its thumbnail by content ID.
type ImageRef struct {
	CID      string `json:"cid"`
	ThumbCID string `json:"thumb_cid"`
	Mime     string `json:"mime"`
	Width    int    `json:"w"`
	Height   int    `json:"h"`
	Size     int64  `json:"size"`
	Filename string `json:"filename,omitempty"`
}

// Post is a thread opener (Thread == "") or a reply.
type Post struct {
	V          int            `json:"v"`
	Board      string         `json:"board"`
	Thread     string         `json:"thread,omitempty"`
	ThreadSalt []byte         `json:"thread_salt,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	Name       string         `json:"name,omitempty"`
	Body       string         `json:"body"`
	Image      *ImageRef      `json:"image,omitempty"`
	Sage       bool           `json:"sage,omitempty"`
	Time       int64          `json:"time"`
	Author     keys.PublicKey `json:"author"`
	Nonce      uint64         `json:"nonce"`
	Sig        []byte         `json:"sig,omitempty"`
}

// IsOP reports whether p starts a thread.
func (p *Post) IsOP() bool { return p.Thread == "" }

// ThreadID returns the id of the thread p belongs to.
func (p *Post) ThreadID() string {
	if p.IsOP() {
		return p.ID()
	}
	return p.Thread
}

func (p *Post) unsigned() []byte {
	c := *p
	c.Sig = nil
	b, err := json.Marshal(&c)
	if err != nil {
		panic(err)
	}
	return append([]byte(postDomain), b...)
}

// Encode returns the canonical wire encoding.
func (p *Post) Encode() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return b
}

// ID is the content address of the signed post.
func (p *Post) ID() string { return hashID(p.Encode()) }

func hashID(b []byte) string {
	h := sha256.Sum256(b)
	return strings.ToLower(b32.EncodeToString(h[:]))
}

// ShortID is the post number shown in the UI.
func ShortID(id string) string {
	if len(id) > 10 {
		return id[:10]
	}
	return id
}

// PosterID is the per-thread poster tag shown next to "Anonymous".
func (p *Post) PosterID() string {
	h := sha256.Sum256(p.Author)
	return b32.EncodeToString(h[:5])
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for i := 0; i < len(h); i += 8 {
		w := binary.BigEndian.Uint64(h[i : i+8])
		if w != 0 {
			return n + bits.LeadingZeros64(w)
		}
		n += 64
	}
	return n
}

func (p *Post) powHash() [32]byte { return sha256.Sum256(p.unsigned()) }

// Seal assigns the author key, solves the proof of work and signs the post.
// For a new thread it also picks a random thread salt.
func (p *Post) Seal(posterSecret ed25519.PrivateKey, threadSalt []byte, powBits int) error {
	if p.IsOP() {
		threadSalt = make([]byte, 16)
		if _, err := rand.Read(threadSalt); err != nil {
			return err
		}
		p.ThreadSalt = threadSalt
	}
	if len(threadSalt) == 0 {
		return errors.New("reply needs the thread salt")
	}
	sk := keys.ThreadKey(posterSecret, threadSalt)
	p.V = 1
	p.Author = keys.Public(sk)
	p.Sig = nil
	var start [8]byte
	if _, err := rand.Read(start[:]); err != nil {
		return err
	}
	// Proof of work over the unsigned encoding. The nonce sits in the JSON,
	// so each attempt re-marshals; at ~20 bits this is about a second.
	for p.Nonce = binary.LittleEndian.Uint64(start[:]); ; p.Nonce++ {
		if leadingZeroBits(p.powHash()) >= powBits {
			break
		}
	}
	p.Sig = ed25519.Sign(sk, p.unsigned())
	return nil
}

// ParsePost decodes a post and checks that its encoding is canonical, so
// that every node computes the same ID for the same post.
func ParsePost(b []byte) (*Post, error) {
	if len(b) > MaxPostSize {
		return nil, errors.New("post too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Post
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	if !bytes.Equal(p.Encode(), b) {
		return nil, errors.New("post: non-canonical encoding")
	}
	return &p, nil
}

// Validate applies every rule a node checks before storing or relaying a
// post. Rules that need other posts (the thread's salt, tombstones) are
// checked by the store.
func (p *Post) Validate(m *manifest.Payload, now time.Time) error {
	if p.V != 1 {
		return fmt.Errorf("unsupported post version %d", p.V)
	}
	if _, ok := m.Board(p.Board); !ok {
		return fmt.Errorf("unknown board %q", p.Board)
	}
	if len(p.Author) != ed25519.PublicKeySize {
		return errors.New("bad author key")
	}
	if !ed25519.Verify(ed25519.PublicKey(p.Author), p.unsigned(), p.Sig) {
		return errors.New("bad signature")
	}
	if leadingZeroBits(p.powHash()) < m.Limits.PoWBits {
		return errors.New("insufficient proof of work")
	}
	if time.Unix(p.Time, 0).After(now.Add(MaxClockSkew)) {
		return errors.New("post time is in the future")
	}
	if p.Time <= 0 {
		return errors.New("missing post time")
	}
	for name, s := range map[string]string{"subject": p.Subject, "name": p.Name, "body": p.Body} {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%s is not valid UTF-8", name)
		}
	}
	if utf8.RuneCountInString(p.Body) > m.Limits.MaxBodyChars {
		return errors.New("comment too long")
	}
	if utf8.RuneCountInString(p.Subject) > maxSubject || utf8.RuneCountInString(p.Name) > maxName {
		return errors.New("subject or name too long")
	}
	if p.IsOP() {
		if len(p.ThreadSalt) != 16 {
			return errors.New("thread opener needs a 16-byte thread salt")
		}
		if m.Limits.OPImageRequired && p.Image == nil {
			return errors.New("a new thread needs an image")
		}
	} else {
		if len(p.ThreadSalt) != 0 || p.Subject != "" {
			return errors.New("replies carry no thread salt or subject")
		}
		if len(p.Thread) != 52 {
			return errors.New("bad thread id")
		}
	}
	if p.Image == nil && strings.TrimSpace(p.Body) == "" {
		return errors.New("empty post")
	}
	if im := p.Image; im != nil {
		if !validCID(im.CID) || !validCID(im.ThumbCID) {
			return errors.New("bad image content id")
		}
		if im.Size <= 0 || im.Size > m.Limits.MaxImageBytes {
			return errors.New("image too large")
		}
		switch im.Mime {
		case "image/jpeg", "image/png", "image/gif":
		default:
			return fmt.Errorf("unsupported image type %q", im.Mime)
		}
		if im.Width <= 0 || im.Height <= 0 || im.Width > 10000 || im.Height > 10000 {
			return errors.New("bad image dimensions")
		}
		if utf8.RuneCountInString(im.Filename) > maxFile || !utf8.ValidString(im.Filename) {
			return errors.New("bad file name")
		}
	}
	return nil
}

// Tombstone is a moderator's signed order to delete a post. Deleting an
// opener deletes the whole thread.
type Tombstone struct {
	V      int            `json:"v"`
	Target string         `json:"target"`
	Board  string         `json:"board"`
	Reason string         `json:"reason,omitempty"`
	Time   int64          `json:"time"`
	Mod    keys.PublicKey `json:"mod"`
	Sig    []byte         `json:"sig,omitempty"`
}

func (t *Tombstone) unsigned() []byte {
	c := *t
	c.Sig = nil
	b, err := json.Marshal(&c)
	if err != nil {
		panic(err)
	}
	return append([]byte(tombstoneDomain), b...)
}

// Encode returns the canonical wire encoding.
func (t *Tombstone) Encode() []byte {
	b, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}
	return b
}

// ID is the content address of the tombstone.
func (t *Tombstone) ID() string { return hashID(t.Encode()) }

// Sign signs the tombstone with a moderator key.
func (t *Tombstone) Sign(sk ed25519.PrivateKey) {
	t.V = 1
	t.Mod = keys.Public(sk)
	t.Sig = ed25519.Sign(sk, t.unsigned())
}

// ParseTombstone decodes a tombstone, requiring canonical encoding.
func ParseTombstone(b []byte) (*Tombstone, error) {
	if len(b) > 4096 {
		return nil, errors.New("tombstone too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var t Tombstone
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("tombstone: %w", err)
	}
	if !bytes.Equal(t.Encode(), b) {
		return nil, errors.New("tombstone: non-canonical encoding")
	}
	return &t, nil
}

// Validate checks the tombstone against the manifest's moderator list.
func (t *Tombstone) Validate(m *manifest.Payload) error {
	if t.V != 1 {
		return errors.New("unsupported tombstone version")
	}
	if !m.IsModerator(t.Mod) {
		return errors.New("tombstone not signed by a moderator")
	}
	if !ed25519.Verify(ed25519.PublicKey(t.Mod), t.unsigned(), t.Sig) {
		return errors.New("bad tombstone signature")
	}
	if len(t.Target) != 52 {
		return errors.New("bad tombstone target")
	}
	if len(t.Reason) > MaxReason || !utf8.ValidString(t.Reason) {
		return errors.New("bad tombstone reason")
	}
	return nil
}

// validCID accepts the CIDv1 raw sha2-256 strings produced by package blob:
// "b" + 58 base32 characters.
func validCID(s string) bool {
	if len(s) != 59 || s[0] != 'b' {
		return false
	}
	for _, c := range s[1:] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
