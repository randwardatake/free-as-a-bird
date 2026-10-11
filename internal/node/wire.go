package node

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// maxFrame bounds one length-prefixed response on a stream.
	maxFrame = 8 << 20
	// maxRequestFrame bounds a sync request. The largest one lists
	// maxIDsPerRequest ids of 52 characters, about 27 KB.
	maxRequestFrame = 64 << 10
)

func writeFrame(w io.Writer, b []byte) error {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(b)))
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r *bufio.Reader, limit int) ([]byte, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > uint64(limit) {
		return nil, fmt.Errorf("frame of %d bytes exceeds limit %d", n, limit)
	}
	// Grow the buffer as bytes arrive instead of allocating the length the
	// peer claims: a peer that announces 8 MB and sends nothing must not
	// cost us 8 MB per stream.
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}

func readJSON(r *bufio.Reader, v any, limit int) error {
	b, err := readFrame(r, limit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("malformed message")
	}
	return nil
}
