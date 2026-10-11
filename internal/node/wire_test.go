package node

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/randwardatake/free-as-a-bird/internal/board"
)

func frame(declared uint64, body []byte) *bufio.Reader {
	hdr := binary.AppendUvarint(nil, declared)
	return bufio.NewReader(bytes.NewReader(append(hdr, body...)))
}

func TestReadFrameLimits(t *testing.T) {
	if _, err := readFrame(frame(maxRequestFrame+1, nil), maxRequestFrame); err == nil {
		t.Error("frame over the limit accepted")
	}
	got, err := readFrame(frame(5, []byte("hello")), maxRequestFrame)
	if err != nil || string(got) != "hello" {
		t.Errorf("readFrame = %q, %v", got, err)
	}
	if _, err := readFrame(frame(10, []byte("short")), maxRequestFrame); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated frame: %v", err)
	}
}

// A peer announcing a huge frame and sending almost nothing must not make
// us allocate what it announced.
func TestReadFrameDoesNotTrustDeclaredLength(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 20 {
		readFrame(frame(maxFrame, []byte("tiny")), maxFrame)
	}
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Errorf("20 truncated 8 MB frames allocated %d bytes", n)
	}
}

// Worst-case responses must fit one frame, or a thread or the tombstone
// list can never be synced.
func TestWorstCaseResponsesFitFrame(t *testing.T) {
	size := func(n, item int) int {
		items := make([][]byte, n)
		for i := range items {
			items[i] = bytes.Repeat([]byte{0xff}, item)
		}
		b, err := json.Marshal(&syncResp{Items: items})
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	if n := size(maxPostsPerRequest, board.MaxPostSize); n > maxFrame {
		t.Errorf("%d posts of %d bytes: %d byte response > %d", maxPostsPerRequest, board.MaxPostSize, n, maxFrame)
	}
	if n := size(maxIDsPerRequest, 4096); n > maxFrame {
		t.Errorf("%d tombstones: %d byte response > %d", maxIDsPerRequest, n, maxFrame)
	}
	req, _ := json.Marshal(&syncReq{Op: "tombstones", IDs: strings.Fields(strings.Repeat(strings.Repeat("a", 52)+" ", maxIDsPerRequest))})
	if len(req) > maxRequestFrame {
		t.Errorf("largest request %d bytes > %d", len(req), maxRequestFrame)
	}
}
