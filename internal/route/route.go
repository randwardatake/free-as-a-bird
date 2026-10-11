// Package route holds the pure cryptography of free-as-a-bird's own onion routing
// layer: deriving a node's X25519 key from its ed25519 identity, the ntor
// handshake that gives a circuit hop its forward and backward keys, the
// fixed-size cell codec, and the onion wrap/unwrap used to send a cell
// through several relays so that no relay sees more than its neighbours.
//
// Nothing here touches the network. The node package drives it over libp2p
// streams; see docs/ROUTING.md.
package route

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DHKeyFromSeed derives a node's static X25519 key from its ed25519 seed.
// ed25519 signing keys and X25519 DH keys live on the same curve, but a key
// must serve one purpose, so we derive a fresh scalar rather than converting
// the signing key. The result is deterministic: the same node key always
// gives the same route key.
func DHKeyFromSeed(seed []byte) (*ecdh.PrivateKey, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, nil, []byte("free-as-a-bird/route-dh/v1")), raw); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// ntor handshake, the construction Tor documents in tor-spec. It gives the
// client an authenticated, forward-secret shared secret with a relay whose
// static public key and id the client already knows from the land record or
// peer record. We reimplement it here over crypto/ecdh.
const protoID = "free-as-a-bird-route-1"

var (
	tMac    = []byte(protoID + ":mac")
	tKey    = []byte(protoID + ":key_extract")
	tVerify = []byte(protoID + ":verify")
	mExpand = []byte(protoID + ":key_expand")
	server  = []byte("Server")
)

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// Keys are the per-hop symmetric keys derived from one handshake. Fwd
// encrypts cells travelling from the client towards the relay; Bwd encrypts
// cells travelling back.
type Keys struct {
	Fwd [chacha20poly1305.KeySize]byte
	Bwd [chacha20poly1305.KeySize]byte
}

func deriveKeys(keySeed []byte) (Keys, error) {
	var k Keys
	r := hkdf.Expand(sha256.New, keySeed, mExpand)
	if _, err := io.ReadFull(r, k.Fwd[:]); err != nil {
		return k, err
	}
	if _, err := io.ReadFull(r, k.Bwd[:]); err != nil {
		return k, err
	}
	return k, nil
}

func keySeedAndAuth(xy, xb, id, b, x, y []byte) (keySeed, auth []byte) {
	var in []byte
	in = append(in, xy...)
	in = append(in, xb...)
	in = append(in, id...)
	in = append(in, b...)
	in = append(in, x...)
	in = append(in, y...)
	in = append(in, protoID...)
	keySeed = mac(in, tKey)
	verify := mac(in, tVerify)
	var ai []byte
	ai = append(ai, verify...)
	ai = append(ai, id...)
	ai = append(ai, b...)
	ai = append(ai, y...)
	ai = append(ai, x...)
	ai = append(ai, protoID...)
	ai = append(ai, server...)
	auth = mac(ai, tMac)
	return keySeed, auth
}

// ClientHandshake holds the state a client keeps between sending CREATE and
// receiving CREATED.
type ClientHandshake struct {
	eph  *ecdh.PrivateKey
	id   []byte
	bPub *ecdh.PublicKey
}

// CreateClient starts a handshake with a relay whose node id and static
// route key are id and b. It returns the state and the 32-byte CREATE
// payload to send (the client's ephemeral public key).
func CreateClient(id []byte, b *ecdh.PublicKey) (*ClientHandshake, []byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &ClientHandshake{eph: eph, id: id, bPub: b}, eph.PublicKey().Bytes(), nil
}

// ServerHandshake answers a CREATE for a relay whose node id is id and whose
// static route key is b. It returns the 64-byte CREATED payload to send back
// and the hop's keys.
func ServerHandshake(id []byte, b *ecdh.PrivateKey, create []byte) (created []byte, k Keys, err error) {
	if len(create) != 32 {
		return nil, k, errors.New("route: bad CREATE length")
	}
	xPub, err := ecdh.X25519().NewPublicKey(create)
	if err != nil {
		return nil, k, fmt.Errorf("route: CREATE key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, k, err
	}
	xy, err := eph.ECDH(xPub)
	if err != nil {
		return nil, k, err
	}
	xb, err := b.ECDH(xPub)
	if err != nil {
		return nil, k, err
	}
	y := eph.PublicKey().Bytes()
	keySeed, auth := keySeedAndAuth(xy, xb, id, b.PublicKey().Bytes(), create, y)
	if k, err = deriveKeys(keySeed); err != nil {
		return nil, k, err
	}
	return append(append([]byte{}, y...), auth...), k, nil
}

// Finish completes the client side from a CREATED payload, checking the
// relay's authentication before returning the hop's keys.
func (h *ClientHandshake) Finish(created []byte) (k Keys, err error) {
	if len(created) != 64 {
		return k, errors.New("route: bad CREATED length")
	}
	y, auth := created[:32], created[32:]
	yPub, err := ecdh.X25519().NewPublicKey(y)
	if err != nil {
		return k, fmt.Errorf("route: CREATED key: %w", err)
	}
	xy, err := h.eph.ECDH(yPub)
	if err != nil {
		return k, err
	}
	xb, err := h.eph.ECDH(h.bPub)
	if err != nil {
		return k, err
	}
	x := h.eph.PublicKey().Bytes()
	keySeed, want := keySeedAndAuth(xy, xb, h.id, h.bPub.Bytes(), x, y)
	if subtle.ConstantTimeCompare(auth, want) != 1 {
		return k, errors.New("route: relay authentication failed")
	}
	return deriveKeys(keySeed)
}

// Cells.
//
// Everything on a circuit is a fixed-size cell so that a relay cannot tell
// cells apart by length. One cell is CellSize bytes:
//
//	[2]  command
//	[16] circuit id (rewritten at each hop)
//	[2]  body length
//	[..] body, zero-padded to CellSize

const (
	CellSize    = 512
	cellHdr     = 2 + 16 + 2
	MaxCellBody = CellSize - cellHdr
)

// Cell commands.
const (
	CmdCreate  uint16 = 1
	CmdCreated uint16 = 2
	CmdRelay   uint16 = 3
	CmdDestroy uint16 = 4
)

// CircID identifies a circuit on one hop's stream.
type CircID [16]byte

// Cell is one fixed-size unit on a circuit.
type Cell struct {
	Cmd  uint16
	Circ CircID
	Body []byte // at most MaxCellBody; the wire form is zero-padded
}

// Marshal encodes a cell to exactly CellSize bytes.
func (c Cell) Marshal() ([]byte, error) {
	if len(c.Body) > MaxCellBody {
		return nil, fmt.Errorf("route: cell body %d exceeds %d", len(c.Body), MaxCellBody)
	}
	buf := make([]byte, CellSize)
	binary.BigEndian.PutUint16(buf[0:], c.Cmd)
	copy(buf[2:18], c.Circ[:])
	binary.BigEndian.PutUint16(buf[18:], uint16(len(c.Body)))
	copy(buf[cellHdr:], c.Body)
	return buf, nil
}

// ParseCell decodes exactly CellSize bytes into a cell.
func ParseCell(buf []byte) (Cell, error) {
	if len(buf) != CellSize {
		return Cell{}, fmt.Errorf("route: cell is %d bytes, want %d", len(buf), CellSize)
	}
	n := binary.BigEndian.Uint16(buf[18:])
	if int(n) > MaxCellBody {
		return Cell{}, errors.New("route: cell body length out of range")
	}
	var c Cell
	c.Cmd = binary.BigEndian.Uint16(buf[0:])
	copy(c.Circ[:], buf[2:18])
	c.Body = append([]byte(nil), buf[cellHdr:cellHdr+int(n)]...)
	return c, nil
}

// Onion layering.
//
// A Layer encrypts in one direction with a counter nonce. It never reuses a
// nonce for a given key: both ends start at zero and step in lock-step, so
// the Nth cell a hop sends and the Nth cell its peer opens use the same
// nonce. Cells must therefore be opened in the order they were sealed, which
// a reliable libp2p stream preserves.
type Layer struct {
	aead    cipher.AEAD
	counter uint64
}

// NewLayer makes a layer for a 32-byte key.
func NewLayer(key []byte) (*Layer, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Layer{aead: a}, nil
}

func (l *Layer) nonce() []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(n[4:], l.counter)
	l.counter++
	return n[:]
}

// Seal encrypts one layer around plaintext.
func (l *Layer) Seal(plaintext []byte) []byte {
	return l.aead.Seal(nil, l.nonce(), plaintext, nil)
}

// Open removes one layer. It errors if the layer was tampered with or if
// cells arrived out of order.
func (l *Layer) Open(ciphertext []byte) ([]byte, error) {
	return l.aead.Open(nil, l.nonce(), ciphertext, nil)
}

// Overhead is the bytes one layer adds (nonce is implicit, so just the tag).
const Overhead = chacha20poly1305.Overhead

// WrapOnion seals plaintext under each layer in turn, last hop first, so
// that the first relay peels the outermost layer. layers are ordered from
// the client outward (layers[0] is the first hop).
func WrapOnion(layers []*Layer, plaintext []byte) []byte {
	b := plaintext
	for i := len(layers) - 1; i >= 0; i-- {
		b = layers[i].Seal(b)
	}
	return b
}

// Sealed box: one-shot public-key encryption to a relay or land's static
// X25519 key, used to hand an introduction point an INTRODUCE payload it
// cannot read. A fresh ephemeral key per message makes a fixed nonce safe.
// Layout: ephemeral_pub(32) || ChaCha20-Poly1305 ciphertext, with the
// ephemeral public key bound in as associated data.

var sealNonce [chacha20poly1305.NonceSize]byte

func sealKey(shared []byte) ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte("free-as-a-bird/route-seal/v1")), key)
	return key, err
}

// SealTo encrypts plaintext so that only the holder of pub's private key can
// read it.
func SealTo(pub *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := sealKey(shared)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	return append(ephPub, aead.Seal(nil, sealNonce[:], plaintext, ephPub)...), nil
}

// OpenSealed reverses SealTo with the recipient's private key.
func OpenSealed(priv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < 32 {
		return nil, errors.New("route: sealed box too short")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	key, err := sealKey(shared)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, sealNonce[:], sealed[32:], sealed[:32])
}
