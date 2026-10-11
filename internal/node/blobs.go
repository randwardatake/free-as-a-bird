package node

import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/p2psite/internal/blob"
	"github.com/randwardatake/p2psite/internal/board"
)

// The blob protocol fetches one image or thumbnail by CID. The requester
// checks the bytes against the CID, so a lying peer only wastes bandwidth.

type fetchReq struct {
	cid     string
	hint    peer.ID
	attempt int
}

// fetchBackoff is the wait before each retry. A peer that just received a
// post often has not finished downloading its image yet, so the first retry
// comes quickly. After the last one the periodic repair pass takes over.
var fetchBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 45 * time.Second}

// wantImages queues a post's thumbnail and image for download.
func (n *Node) wantImages(p *board.Post, hint peer.ID) {
	if p.Image == nil {
		return
	}
	for _, c := range []string{p.Image.ThumbCID, p.Image.CID} {
		n.enqueue(c, hint)
	}
}

func (n *Node) enqueue(c string, hint peer.ID) {
	if n.Blobs.Has(c) {
		return
	}
	if _, busy := n.inflight.LoadOrStore(c, struct{}{}); busy {
		return
	}
	select {
	case n.fetch <- fetchReq{cid: c, hint: hint}:
	default:
		n.inflight.Delete(c) // queue full; the repair pass will retry
	}
}

// repairBlobs queues every referenced blob that is not on disk yet.
func (n *Node) repairBlobs() {
	for _, c := range n.Store.BlobRefs() {
		n.enqueue(c, "")
	}
}

// freeBlobs deletes blobs that no stored post references any more.
func (n *Node) freeBlobs(cids []string) {
	for _, c := range cids {
		if !n.Store.Referenced(c) {
			if err := n.Blobs.Delete(c); err != nil {
				n.log.Warn("delete blob", "cid", c, "err", err)
			}
		}
	}
}

func (n *Node) fetchWorker() {
	for {
		var req fetchReq
		select {
		case <-n.ctx.Done():
			return
		case req = <-n.fetch:
		}
		if n.fetchOne(req) || req.attempt >= len(fetchBackoff) {
			n.inflight.Delete(req.cid)
			continue
		}
		next := fetchReq{cid: req.cid, attempt: req.attempt + 1}
		time.AfterFunc(fetchBackoff[req.attempt], func() {
			select {
			case n.fetch <- next:
			case <-n.ctx.Done():
			default:
				n.inflight.Delete(next.cid)
			}
		})
	}
}

// fetchOne tries to download one blob. It reports whether nothing more
// needs to be done.
func (n *Node) fetchOne(req fetchReq) bool {
	if n.Blobs.Has(req.cid) || !n.Store.Referenced(req.cid) {
		return true
	}
	candidates := n.dataPeers()
	if req.hint != "" && n.direct(req.hint) {
		candidates = append([]peer.ID{req.hint}, candidates...)
	}
	limit := int(n.Manifest().Payload.Limits.MaxImageBytes)
	tried := map[peer.ID]bool{}
	for _, p := range candidates {
		if tried[p] || p == n.host.ID() || len(tried) >= 6 {
			continue
		}
		tried[p] = true
		data, err := n.getBlob(p, req.cid, limit)
		if err != nil {
			continue
		}
		if err := n.Blobs.PutVerified(req.cid, data); err != nil {
			n.log.Warn("peer sent bad blob", "peer", p, "cid", req.cid, "err", err)
			continue
		}
		return true
	}
	return false
}

func (n *Node) getBlob(p peer.ID, c string, limit int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	s, err := n.host.NewStream(ctx, p, n.proto("blob"))
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(time.Minute))
	if err := writeFrame(s, []byte(c)); err != nil {
		s.Reset()
		return nil, err
	}
	s.CloseWrite()
	r := bufio.NewReader(s)
	status, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, errors.New("peer does not have blob")
	}
	return readFrame(r, limit)
}

func (n *Node) handleBlob(s network.Stream) {
	defer s.Close()
	s.SetDeadline(time.Now().Add(time.Minute))
	c, err := readFrame(bufio.NewReader(s), 128)
	if err != nil {
		s.Reset()
		return
	}
	// Only serve blobs that a live post references, so deleted images stop
	// spreading even if a copy is still on disk.
	var data []byte
	if n.Store.Referenced(string(c)) {
		data, err = n.Blobs.Get(string(c))
	}
	if data == nil || err != nil || blob.Verify(string(c), data) != nil {
		s.Write([]byte{1})
		return
	}
	if _, err := s.Write([]byte{0}); err != nil {
		s.Reset()
		return
	}
	if err := writeFrame(s, data); err != nil {
		s.Reset()
		return
	}
	io.Copy(io.Discard, s)
}
