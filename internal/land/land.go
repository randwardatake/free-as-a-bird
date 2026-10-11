// Package land implements land identity (see docs/LANDS.md): the master
// secret a land is owned by, its BIP-39 backup phrase, the land signing key
// and route key derived from it, and the signed registration record that
// binds a land name to those keys.
//
// The phrase is only an encoding of the master secret: the words carry its
// raw entropy plus the BIP-39 checksum. There is no PBKDF2 stretching and no
// passphrase, so a phrase from a cryptocurrency wallet is not interchangeable
// with one from here even though the wordlist is the same.
package land

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Phrase lengths. Words24 is the default: a lost land cannot be reissued.
const (
	Words12 = 12 // 128-bit master secret
	Words24 = 24 // 256-bit master secret
)

const (
	landInfo  = "free-as-a-bird/land/v1"
	routeInfo = "free-as-a-bird/land-route/v1"
)

//go:embed english.txt
var englishTxt string

// wordlist is the BIP-39 English wordlist; index is its inverse.
var (
	wordlist = strings.Fields(englishTxt)
	index    = make(map[string]int, len(wordlist))
)

func init() {
	if len(wordlist) != 2048 {
		panic(fmt.Sprintf("land: wordlist has %d words, want 2048", len(wordlist)))
	}
	for i, w := range wordlist {
		index[w] = i
	}
}

// Master is a land's master secret. Whoever holds it owns the land.
type Master struct {
	secret []byte // 16 or 32 bytes of entropy
}

// NewMaster generates a fresh master secret whose phrase has the given
// number of words (Words12 or Words24).
func NewMaster(words int) (*Master, error) {
	n, err := entropyLen(words)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &Master{secret: secret}, nil
}

func entropyLen(words int) (int, error) {
	switch words {
	case Words12:
		return 16, nil
	case Words24:
		return 32, nil
	}
	return 0, fmt.Errorf("phrase must be %d or %d words, not %d", Words12, Words24, words)
}

// String keeps the secret out of logs and %v output.
func (m *Master) String() string { return "land.Master(redacted)" }

// Phrase returns the backup phrase: space-separated BIP-39 words that encode
// the master secret and a checksum.
func (m *Master) Phrase() string {
	cs := len(m.secret) / 4 // checksum bits: 4 for 12 words, 8 for 24
	h := sha256.Sum256(m.secret)
	buf := append(append([]byte{}, m.secret...), h[0])
	words := make([]string, (len(m.secret)*8+cs)/11)
	for i := range words {
		words[i] = wordlist[getBits(buf, i*11, 11)]
	}
	return strings.Join(words, " ")
}

// ParsePhrase recovers a master secret from its backup phrase. Case and
// surrounding or repeated whitespace are ignored.
func ParsePhrase(phrase string) (*Master, error) {
	words := strings.Fields(strings.ToLower(phrase))
	n, err := entropyLen(len(words))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n+1)
	for i, w := range words {
		v, ok := index[w]
		if !ok {
			return nil, fmt.Errorf("word %d (%q) is not in the BIP-39 English wordlist", i+1, w)
		}
		setBits(buf, i*11, 11, v)
	}
	secret, sum := buf[:n], buf[n]
	cs := n / 4
	mask := byte(0xff) << (8 - cs)
	if h := sha256.Sum256(secret); sum != h[0]&mask {
		return nil, errors.New("phrase checksum does not match: a word is wrong or out of order")
	}
	return &Master{secret: secret}, nil
}

// getBits reads n bits of b, most significant first, starting at bit off.
func getBits(b []byte, off, n int) int {
	v := 0
	for i := off; i < off+n; i++ {
		v = v<<1 | int(b[i/8]>>(7-i%8)&1)
	}
	return v
}

// setBits writes the low n bits of v into b at bit off, most significant first.
func setBits(b []byte, off, n, v int) {
	for i := 0; i < n; i++ {
		if v>>(n-1-i)&1 == 1 {
			p := off + i
			b[p/8] |= 1 << (7 - p%8)
		}
	}
}

func (m *Master) derive(info string) []byte {
	r := hkdf.New(sha256.New, m.secret, nil, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err) // hkdf only fails when asked for too much output
	}
	return out
}

// LandKey derives land_secret, the ed25519 key that signs the land's records.
func (m *Master) LandKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(m.derive(landInfo))
}

// RouteKey derives land_onion, the land's static X25519 key for the
// ROUTING.md handshake and its introduction points. It is derived separately
// from LandKey so one key never serves two cryptographic purposes.
func (m *Master) RouteKey() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(m.derive(routeInfo))
	if err != nil {
		panic(err) // any 32 bytes are a valid X25519 private key
	}
	return k
}
