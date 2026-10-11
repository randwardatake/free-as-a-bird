// Package keys handles the ed25519 signing keys used for maintainers,
// moderators and posters, and their on-disk format.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// PublicKey is an ed25519 public key that marshals to unpadded base64url.
type PublicKey []byte

func (k PublicKey) String() string { return base64.RawURLEncoding.EncodeToString(k) }

func (k PublicKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *PublicKey) UnmarshalText(b []byte) error {
	pk, err := ParsePublicKey(string(b))
	if err != nil {
		return err
	}
	*k = pk
	return nil
}

// Equal reports whether two keys are byte-identical.
func (k PublicKey) Equal(o PublicKey) bool { return string(k) == string(o) }

// ParsePublicKey decodes a base64url public key.
func ParsePublicKey(s string) (PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: want %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return PublicKey(b), nil
}

// Generate returns a fresh ed25519 private key.
func Generate() (ed25519.PrivateKey, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	return sk, err
}

// Public returns the public half of sk.
func Public(sk ed25519.PrivateKey) PublicKey {
	return PublicKey(sk.Public().(ed25519.PublicKey))
}

// Save writes the private key seed to path with 0600 permissions.
// It refuses to overwrite an existing file.
func Save(path string, sk ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, base64.RawURLEncoding.EncodeToString(sk.Seed())+"\n")
	return err
}

// Load reads a private key written by Save.
func Load(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %v are too open, run: chmod 600 %s", path, st.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New(path + ": bad key length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadOrCreate loads the key at path, creating it first if it does not exist.
func LoadOrCreate(path string) (ed25519.PrivateKey, error) {
	sk, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		if sk, err = Generate(); err != nil {
			return nil, err
		}
		if err = Save(path, sk); err != nil {
			return nil, err
		}
	}
	return sk, err
}

// ThreadKey derives the poster key used inside one thread. The same secret
// and salt always give the same key, so a poster keeps one ID within a
// thread, while keys in different threads cannot be linked to each other.
func ThreadKey(secret ed25519.PrivateKey, threadSalt []byte) ed25519.PrivateKey {
	r := hkdf.New(sha256.New, secret.Seed(), threadSalt, []byte("free-as-a-bird/thread-key/v1"))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		panic(err) // hkdf only fails when asked for too much output
	}
	return ed25519.NewKeyFromSeed(seed)
}
