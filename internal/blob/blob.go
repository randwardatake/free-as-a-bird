// Package blob is a content-addressed file store for images and thumbnails.
// Blobs are named by CIDv1 (raw codec, sha2-256), the same IDs IPFS uses, and
// every write is checked against its CID, so a peer cannot slip in different
// bytes under a known name.
package blob

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// Store keeps blobs under dir/xx/<cid>.
type Store struct{ dir string }

// Open creates the store directory if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Sum returns the CID string for data.
func Sum(data []byte) string {
	h, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		panic(err)
	}
	return cid.NewCidV1(cid.Raw, h).String()
}

// Verify checks that data hashes to c.
func Verify(c string, data []byte) error {
	want, err := cid.Decode(c)
	if err != nil {
		return err
	}
	if want.Prefix().Codec != cid.Raw || want.Prefix().MhType != mh.SHA2_256 {
		return errors.New("unsupported CID type")
	}
	if Sum(data) != want.String() {
		return fmt.Errorf("content does not match %s", c)
	}
	return nil
}

func (s *Store) path(c string) (string, error) {
	parsed, err := cid.Decode(c)
	if err != nil || parsed.String() != c || len(c) < 4 {
		return "", fmt.Errorf("bad CID %q", c)
	}
	return filepath.Join(s.dir, c[len(c)-3:len(c)-1], c), nil
}

// Put stores data under its CID and returns the CID.
func (s *Store) Put(data []byte) (string, error) {
	c := Sum(data)
	return c, s.PutVerified(c, data)
}

// PutVerified stores data received from a peer after checking it matches c.
func (s *Store) PutVerified(c string, data []byte) error {
	if err := Verify(c, data); err != nil {
		return err
	}
	p, err := s.path(c)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Get returns the blob's bytes.
func (s *Store) Get(c string) ([]byte, error) {
	p, err := s.path(c)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Has reports whether the blob is stored locally.
func (s *Store) Has(c string) bool {
	p, err := s.path(c)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Delete removes a blob. Missing blobs are not an error.
func (s *Store) Delete(c string) error {
	p, err := s.path(c)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Size returns the total bytes stored.
func (s *Store) Size() (int64, error) {
	var n int64
	err := filepath.WalkDir(s.dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err == nil {
			n += info.Size()
		}
		return err
	})
	return n, err
}
