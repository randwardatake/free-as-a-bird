package node

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/p2psite/internal/board"
	"github.com/randwardatake/p2psite/internal/manifest"
)

// The sync protocol is request/response, one request per stream. It lets a
// node that was offline catch up on manifests, tombstones and posts.

const (
	// maxIDsPerRequest caps id lists and tombstone requests (tombstones are
	// at most 4 KiB, so 500 of them fit one frame).
	maxIDsPerRequest = 500
	// maxPostsPerRequest caps a "posts" request so that even posts of
	// MaxPostSize fit one response frame; JSON base64 grows them by 4/3.
	maxPostsPerRequest = (maxFrame*3/4 - 4096) / board.MaxPostSize
	syncInterval       = time.Minute
	streamTimeout      = 30 * time.Second
)

type syncReq struct {
	Op     string   `json:"op"`
	Board  string   `json:"board,omitempty"`
	Thread string   `json:"thread,omitempty"`
	IDs    []string `json:"ids,omitempty"`
}

type syncResp struct {
	Err      string         `json:"err,omitempty"`
	Manifest []byte         `json:"manifest,omitempty"`
	Digests  []board.Digest `json:"digests,omitempty"`
	IDs      []string       `json:"ids,omitempty"`
	Items    [][]byte       `json:"items,omitempty"`
}

func (n *Node) handleSync(s network.Stream) {
	defer s.Close()
	s.SetDeadline(time.Now().Add(streamTimeout))
	r := bufio.NewReader(s)
	var req syncReq
	if err := readJSON(r, &req, maxRequestFrame); err != nil {
		s.Reset()
		return
	}
	var resp syncResp
	switch req.Op {
	case "manifest":
		resp.Manifest = n.Manifest().Marshal()
	case "digests":
		resp.Digests = n.Store.Digests(req.Board)
	case "thread_ids":
		resp.IDs = n.Store.ThreadPostIDs(req.Thread)
	case "posts":
		if len(req.IDs) > maxPostsPerRequest {
			resp.Err = "too many ids"
		} else {
			resp.Items = n.Store.RawPosts(req.IDs)
		}
	case "tombstone_ids":
		resp.IDs = n.Store.TombstoneIDs()
	case "tombstones":
		if len(req.IDs) > maxIDsPerRequest {
			resp.Err = "too many ids"
		} else {
			resp.Items = n.Store.RawTombstones(req.IDs)
		}
	default:
		resp.Err = "unknown op"
	}
	if err := writeJSON(s, &resp); err != nil {
		s.Reset()
	}
}

func (n *Node) request(ctx context.Context, p peer.ID, req syncReq) (*syncResp, error) {
	ctx, cancel := context.WithTimeout(ctx, streamTimeout)
	defer cancel()
	s, err := n.host.NewStream(ctx, p, n.proto("sync"))
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(streamTimeout))
	if err := writeJSON(s, &req); err != nil {
		s.Reset()
		return nil, err
	}
	s.CloseWrite()
	var resp syncResp
	if err := readJSON(bufio.NewReader(s), &resp, maxFrame); err != nil {
		s.Reset()
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New(resp.Err)
	}
	return &resp, nil
}

// maybeSync syncs with a newly connected peer unless we synced recently.
func (n *Node) maybeSync(p peer.ID) {
	if last, ok := n.lastSync.Load(p); ok && time.Since(last.(time.Time)) < syncInterval {
		return
	}
	// Give identify a moment so we know whether the peer speaks our protocol.
	select {
	case <-time.After(time.Second):
	case <-n.ctx.Done():
		return
	}
	n.syncWith(p)
}

// syncWith pulls everything we are missing from one peer.
func (n *Node) syncWith(p peer.ID) {
	if !n.isMember(p) {
		return
	}
	n.host.ConnManager().Protect(p, memberTag)
	if !n.direct(p) {
		// Relayed only: requests would block on hole punching. If it
		// succeeds, the direct connection triggers a sync of its own.
		return
	}
	n.lastSync.Store(p, time.Now())
	ctx := n.ctx
	start := time.Now()

	if r, err := n.request(ctx, p, syncReq{Op: "manifest"}); err == nil {
		if err := n.AcceptManifest(r.Manifest); err != nil && !errors.Is(err, manifest.ErrNotNewer) {
			n.log.Debug("peer sent bad manifest", "peer", p, "err", err)
		}
	}

	// Tombstones first, so we never fetch posts that are already deleted.
	if r, err := n.request(ctx, p, syncReq{Op: "tombstone_ids"}); err == nil {
		var missing []string
		for _, id := range r.IDs {
			if !n.Store.Has(id) {
				missing = append(missing, id)
			}
		}
		for len(missing) > 0 {
			batch := missing[:min(len(missing), maxIDsPerRequest)]
			missing = missing[len(batch):]
			tr, err := n.request(ctx, p, syncReq{Op: "tombstones", IDs: batch})
			if err != nil {
				break
			}
			for _, raw := range tr.Items {
				if t, err := board.ParseTombstone(raw); err == nil {
					if res, err := n.Store.AddTombstone(t); err == nil {
						n.freeBlobs(res.Freed)
					}
				}
			}
		}
	}

	added := 0
	for _, b := range n.Manifest().Payload.Boards {
		r, err := n.request(ctx, p, syncReq{Op: "digests", Board: b.ID})
		if err != nil {
			continue
		}
		for _, d := range r.Digests {
			// A thread we pruned, deleted or filled differs from the peer's
			// copy by design; fetching it again would only be rejected.
			if n.Store.Settled(d.Thread) || bytes.Equal(n.Store.DigestHash(d.Thread), d.Hash) {
				continue
			}
			added += n.syncThread(ctx, p, d.Thread)
		}
	}
	if added > 0 {
		n.log.Info("synced posts from peer", "peer", p, "posts", added, "took", time.Since(start).Round(time.Millisecond))
	}
}

func (n *Node) syncThread(ctx context.Context, p peer.ID, thread string) int {
	r, err := n.request(ctx, p, syncReq{Op: "thread_ids", Thread: thread})
	if err != nil {
		return 0
	}
	var missing []string
	for _, id := range r.IDs {
		if n.Store.Has(id) {
			continue
		}
		if id == thread {
			// The opener goes first so replies do not wait as orphans.
			missing = append([]string{id}, missing...)
		} else {
			missing = append(missing, id)
		}
	}
	added := 0
	for len(missing) > 0 {
		batch := missing[:min(len(missing), maxPostsPerRequest)]
		missing = missing[len(batch):]
		pr, err := n.request(ctx, p, syncReq{Op: "posts", IDs: batch})
		if err != nil {
			return added
		}
		var ops, replies []*board.Post
		for _, raw := range pr.Items {
			post, err := board.ParsePost(raw)
			if err != nil {
				continue
			}
			if post.IsOP() {
				ops = append(ops, post)
			} else {
				replies = append(replies, post)
			}
		}
		for _, post := range append(ops, replies...) {
			res, err := n.Store.Add(post, time.Now())
			n.freeBlobs(res.Freed)
			if err == nil && res.Added {
				added++
				n.wantImages(post, p)
			}
		}
	}
	return added
}
