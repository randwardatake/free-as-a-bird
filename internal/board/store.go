package board

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/randwardatake/p2psite/internal/manifest"
)

var (
	bucketPosts      = []byte("posts")
	bucketTombstones = []byte("tombstones")
	bucketPruned     = []byte("pruned")
)

// Errors returned by Store.Add. They mean "drop this post", not a fault.
var (
	ErrDeleted    = errors.New("post was deleted by a moderator")
	ErrPruned     = errors.New("thread has fallen off the board")
	ErrThreadFull = errors.New("thread is full")
)

// prunedTTL is how long a pruned thread id is remembered, so that slow peers
// cannot bring the thread back.
const prunedTTL = 30 * 24 * time.Hour

// orphanTTL is how long a reply may wait for its thread opener to arrive.
const orphanTTL = time.Hour

type postIdx struct {
	id, board, thread string
	time              int64
	sage              bool
	cids              []string
}

type threadIdx struct {
	id, board string
	created   int64
	bump      int64
	replies   []*postIdx // sorted by (time, id)
	images    int
}

// Store keeps posts on disk and an index of threads in memory.
type Store struct {
	mu       sync.RWMutex
	db       *bolt.DB
	m        *manifest.Payload
	posts    map[string]*postIdx
	threads  map[string]*threadIdx
	orphans  map[string][]*postIdx // thread id -> replies waiting for the opener
	deleted  map[string]bool       // tombstoned post ids
	tombs    map[string]bool       // tombstone ids
	pruned   map[string]int64      // thread id -> unix time pruned
	blobRefs map[string]int
}

// Result tells the caller what an insert changed.
type Result struct {
	Added bool
	// Freed lists blob CIDs that are no longer referenced by any post and
	// can be deleted from disk.
	Freed []string
}

// Open loads the store from path.
func Open(path string, m *manifest.Payload) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (is another p2psite running on this data dir?)", path, err)
	}
	s := &Store{
		db: db, m: m,
		posts: map[string]*postIdx{}, threads: map[string]*threadIdx{},
		orphans: map[string][]*postIdx{}, deleted: map[string]bool{},
		tombs: map[string]bool{}, pruned: map[string]int64{}, blobRefs: map[string]int{},
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketPosts, bucketTombstones, bucketPruned} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		if err := tx.Bucket(bucketTombstones).ForEach(func(k, v []byte) error {
			t, err := ParseTombstone(v)
			if err != nil {
				return nil // skip unreadable entries
			}
			s.tombs[string(k)] = true
			s.deleted[t.Target] = true
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(bucketPruned).ForEach(func(k, v []byte) error {
			if len(v) == 8 {
				s.pruned[string(k)] = int64(binary.BigEndian.Uint64(v))
			}
			return nil
		}); err != nil {
			return err
		}
		var replies []*Post
		if err := tx.Bucket(bucketPosts).ForEach(func(k, v []byte) error {
			p, err := ParsePost(v)
			if err != nil {
				return nil
			}
			if p.IsOP() {
				s.indexOP(p, string(k))
			} else {
				replies = append(replies, p)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, p := range replies {
			s.indexReply(p, p.ID())
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, t := range s.threads {
		s.recomputeBump(t)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetManifest switches to a newly accepted manifest.
func (s *Store) SetManifest(m *manifest.Payload) {
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
}

// Manifest returns the manifest the store validates against.
func (s *Store) Manifest() *manifest.Payload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m
}

func idxOf(p *Post, id string) *postIdx {
	pi := &postIdx{id: id, board: p.Board, thread: p.ThreadID(), time: p.Time, sage: p.Sage}
	if p.Image != nil {
		pi.cids = []string{p.Image.CID, p.Image.ThumbCID}
	}
	return pi
}

func (s *Store) ref(pi *postIdx, delta int) {
	for _, c := range pi.cids {
		s.blobRefs[c] += delta
		if s.blobRefs[c] <= 0 {
			delete(s.blobRefs, c)
		}
	}
}

func (s *Store) indexOP(p *Post, id string) {
	pi := idxOf(p, id)
	s.posts[id] = pi
	s.ref(pi, 1)
	t := &threadIdx{id: id, board: p.Board, created: p.Time, bump: p.Time}
	if p.Image != nil {
		t.images++
	}
	s.threads[id] = t
	for _, o := range s.orphans[id] {
		if o.board == t.board {
			insertReply(t, o)
		}
	}
	delete(s.orphans, id)
}

func (s *Store) indexReply(p *Post, id string) {
	pi := idxOf(p, id)
	s.posts[id] = pi
	s.ref(pi, 1)
	if t, ok := s.threads[p.Thread]; ok && t.board == p.Board {
		insertReply(t, pi)
		return
	}
	s.orphans[p.Thread] = append(s.orphans[p.Thread], pi)
}

func insertReply(t *threadIdx, pi *postIdx) {
	i := sort.Search(len(t.replies), func(i int) bool {
		r := t.replies[i]
		return r.time > pi.time || r.time == pi.time && r.id > pi.id
	})
	t.replies = slices.Insert(t.replies, i, pi)
	if len(pi.cids) > 0 {
		t.images++
	}
}

func (s *Store) recomputeBump(t *threadIdx) {
	t.bump = t.created
	for i, r := range t.replies {
		if i >= s.m.Limits.BumpLimit {
			break
		}
		if !r.sage && r.time > t.bump {
			t.bump = r.time
		}
	}
}

// Has reports whether a post or tombstone id is already known (stored or
// deleted), so callers can skip fetching it.
func (s *Store) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.posts[id]
	return ok || s.deleted[id] || s.tombs[id]
}

// Settled reports whether this node has stopped accepting posts for a
// thread: it was pruned, deleted by a moderator, or is full. A peer's copy
// of such a thread differs from ours by design, so sync skips it instead of
// fetching posts that Add would reject.
func (s *Store) Settled(thread string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.pruned[thread]; ok || s.deleted[thread] {
		return true
	}
	t, ok := s.threads[thread]
	return ok && len(t.replies) >= 2*s.m.Limits.BumpLimit
}

// Add validates and stores a post.
func (s *Store) Add(p *Post, now time.Time) (Result, error) {
	id := p.ID()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.posts[id]; ok {
		return Result{}, nil
	}
	if s.deleted[id] || s.deleted[p.Thread] {
		return Result{}, ErrDeleted
	}
	if _, ok := s.pruned[p.ThreadID()]; ok {
		return Result{}, ErrPruned
	}
	if err := p.Validate(s.m, now); err != nil {
		return Result{}, err
	}
	if !p.IsOP() {
		if t, ok := s.threads[p.Thread]; ok {
			if t.board != p.Board {
				return Result{}, errors.New("reply board does not match its thread")
			}
			if len(t.replies) >= 2*s.m.Limits.BumpLimit {
				return Result{}, ErrThreadFull
			}
		}
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPosts).Put([]byte(id), p.Encode())
	}); err != nil {
		return Result{}, err
	}
	var t *threadIdx
	if p.IsOP() {
		s.indexOP(p, id)
		t = s.threads[id]
	} else {
		s.indexReply(p, id)
		t = s.threads[p.Thread]
	}
	res := Result{Added: true}
	if t != nil {
		s.recomputeBump(t)
		freed, err := s.pruneBoard(t.board, now)
		if err != nil {
			return res, err
		}
		res.Freed = freed
		if _, gone := s.posts[id]; !gone {
			// The post landed in a thread that was immediately pruned.
			return res, ErrPruned
		}
	}
	return res, nil
}

// pruneBoard drops the threads past the board's last page.
func (s *Store) pruneBoard(board string, now time.Time) ([]string, error) {
	ts := s.boardThreads(board)
	max := s.m.Limits.MaxThreads()
	if len(ts) <= max {
		return nil, nil
	}
	var freed []string
	for _, t := range ts[max:] {
		f, err := s.deleteThread(t, func(tx *bolt.Tx) error {
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], uint64(now.Unix()))
			s.pruned[t.id] = now.Unix()
			return tx.Bucket(bucketPruned).Put([]byte(t.id), v[:])
		})
		if err != nil {
			return freed, err
		}
		freed = append(freed, f...)
	}
	return freed, nil
}

// deleteThread removes a thread and its replies; extra runs in the same
// transaction.
func (s *Store) deleteThread(t *threadIdx, extra func(*bolt.Tx) error) ([]string, error) {
	victims := append([]*postIdx{s.posts[t.id]}, t.replies...)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPosts)
		for _, v := range victims {
			if v == nil {
				continue
			}
			if err := b.Delete([]byte(v.id)); err != nil {
				return err
			}
		}
		if extra != nil {
			return extra(tx)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	delete(s.threads, t.id)
	return s.unindex(victims), nil
}

func (s *Store) unindex(victims []*postIdx) []string {
	var freed []string
	for _, v := range victims {
		if v == nil {
			continue
		}
		delete(s.posts, v.id)
		s.ref(v, -1)
		for _, c := range v.cids {
			if s.blobRefs[c] == 0 {
				freed = append(freed, c)
			}
		}
	}
	return freed
}

// AddTombstone validates a moderator deletion, applies it and remembers it.
func (s *Store) AddTombstone(t *Tombstone) (Result, error) {
	id := t.ID()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tombs[id] {
		return Result{}, nil
	}
	if err := t.Validate(s.m); err != nil {
		return Result{}, err
	}
	var victims []*postIdx
	var thread *threadIdx
	if th, ok := s.threads[t.Target]; ok {
		thread = th
	} else if pi, ok := s.posts[t.Target]; ok {
		victims = []*postIdx{pi}
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTombstones).Put([]byte(id), t.Encode())
	})
	if err != nil {
		return Result{}, err
	}
	s.tombs[id] = true
	s.deleted[t.Target] = true
	res := Result{Added: true}
	if thread != nil {
		res.Freed, err = s.deleteThread(thread, nil)
		delete(s.orphans, thread.id)
		return res, err
	}
	if len(victims) > 0 {
		err = s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucketPosts).Delete([]byte(t.Target))
		})
		if err != nil {
			return res, err
		}
		if th, ok := s.threads[victims[0].thread]; ok {
			th.replies = slices.DeleteFunc(th.replies, func(r *postIdx) bool { return r.id == t.Target })
			if len(victims[0].cids) > 0 {
				th.images--
			}
			s.recomputeBump(th)
		}
		if orph := s.orphans[victims[0].thread]; len(orph) > 0 {
			s.orphans[victims[0].thread] = slices.DeleteFunc(orph, func(r *postIdx) bool { return r.id == t.Target })
		}
		res.Freed = s.unindex(victims)
	}
	return res, nil
}

// Maintain drops replies whose opener never arrived and forgets old pruned
// thread ids. Call it periodically.
func (s *Store) Maintain(now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var victims []*postIdx
	for tid, orph := range s.orphans {
		kept := orph[:0]
		for _, o := range orph {
			if now.Sub(time.Unix(o.time, 0)) > orphanTTL {
				victims = append(victims, o)
			} else {
				kept = append(kept, o)
			}
		}
		if len(kept) == 0 {
			delete(s.orphans, tid)
		} else {
			s.orphans[tid] = kept
		}
	}
	var expired []string
	for id, at := range s.pruned {
		if now.Sub(time.Unix(at, 0)) > prunedTTL {
			expired = append(expired, id)
		}
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, v := range victims {
			if err := tx.Bucket(bucketPosts).Delete([]byte(v.id)); err != nil {
				return err
			}
		}
		for _, id := range expired {
			if err := tx.Bucket(bucketPruned).Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, id := range expired {
		delete(s.pruned, id)
	}
	return s.unindex(victims), nil
}

// boardThreads returns the board's threads, most recently bumped first.
func (s *Store) boardThreads(board string) []*threadIdx {
	var ts []*threadIdx
	for _, t := range s.threads {
		if t.board == board {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].bump != ts[j].bump {
			return ts[i].bump > ts[j].bump
		}
		return ts[i].id > ts[j].id
	})
	return ts
}

func (s *Store) load(ids []string) []*Post {
	out := make([]*Post, 0, len(ids))
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPosts)
		for _, id := range ids {
			if v := b.Get([]byte(id)); v != nil {
				if p, err := ParsePost(v); err == nil {
					out = append(out, p)
				}
			}
		}
		return nil
	})
	return out
}

// ThreadView is a thread prepared for rendering.
type ThreadView struct {
	OP      *Post
	Replies []*Post
	// Omitted counts replies not included in Replies.
	Omitted       int
	ReplyCount    int
	ImageCount    int
	Bump          int64
	BumpLimitHit  bool
	OmittedImages int
}

// Page returns one index page: threads with their last `preview` replies.
// The second value is the number of pages that currently have threads.
func (s *Store) Page(board string, page, preview int) ([]ThreadView, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts := s.boardThreads(board)
	per := s.m.Limits.ThreadsPerPage
	pages := (len(ts) + per - 1) / per
	if page < 0 || page*per >= len(ts) {
		return nil, pages
	}
	end := min(len(ts), (page+1)*per)
	var out []ThreadView
	for _, t := range ts[page*per : end] {
		out = append(out, s.view(t, preview))
	}
	return out, pages
}

// Catalog returns every thread on a board with no replies loaded.
func (s *Store) Catalog(board string) []ThreadView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ThreadView
	for _, t := range s.boardThreads(board) {
		out = append(out, s.view(t, 0))
	}
	return out
}

// Thread returns a whole thread.
func (s *Store) Thread(id string) (ThreadView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.threads[id]
	if !ok {
		return ThreadView{}, false
	}
	return s.view(t, -1), true
}

func (s *Store) view(t *threadIdx, preview int) ThreadView {
	shown := t.replies
	if preview >= 0 && len(shown) > preview {
		shown = shown[len(shown)-preview:]
	}
	ids := []string{t.id}
	shownImages := 0
	for _, r := range shown {
		ids = append(ids, r.id)
		if len(r.cids) > 0 {
			shownImages++
		}
	}
	ps := s.load(ids)
	v := ThreadView{
		ReplyCount:   len(t.replies),
		ImageCount:   t.images,
		Bump:         t.bump,
		BumpLimitHit: len(t.replies) >= s.m.Limits.BumpLimit,
		Omitted:      len(t.replies) - len(shown),
	}
	opImages := 0
	if len(ps) > 0 && ps[0].IsOP() {
		v.OP, v.Replies = ps[0], ps[1:]
		if v.OP.Image != nil {
			opImages = 1
		}
	}
	v.OmittedImages = t.images - opImages - shownImages
	return v
}

// Post returns one stored post.
func (s *Store) Post(id string) (*Post, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.posts[id]; !ok {
		return nil, false
	}
	ps := s.load([]string{id})
	if len(ps) == 0 {
		return nil, false
	}
	return ps[0], true
}

// RawPosts returns the encodings of the requested posts that are stored.
func (s *Store) RawPosts(ids []string) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out [][]byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPosts)
		for _, id := range ids {
			if v := b.Get([]byte(id)); v != nil {
				out = append(out, slices.Clone(v))
			}
		}
		return nil
	})
	return out
}

// Digest summarises one thread for sync: peers compare digests and fetch
// only threads that differ.
type Digest struct {
	Thread string `json:"t"`
	Count  int    `json:"n"`
	Hash   []byte `json:"h"`
}

// Digests returns a digest per thread on the board.
func (s *Store) Digests(board string) []Digest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Digest
	for _, t := range s.boardThreads(board) {
		ids := s.threadIDs(t)
		h := sha256.Sum256([]byte(strings.Join(ids, ",")))
		out = append(out, Digest{Thread: t.id, Count: len(ids), Hash: h[:]})
	}
	return out
}

func (s *Store) threadIDs(t *threadIdx) []string {
	ids := make([]string, 0, len(t.replies)+1)
	ids = append(ids, t.id)
	for _, r := range t.replies {
		ids = append(ids, r.id)
	}
	sort.Strings(ids)
	return ids
}

// ThreadPostIDs lists the ids in a thread, opener included.
func (s *Store) ThreadPostIDs(thread string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.threads[thread]
	if !ok {
		return nil
	}
	return s.threadIDs(t)
}

// DigestHash returns the local digest of a thread, or nil.
func (s *Store) DigestHash(thread string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.threads[thread]
	if !ok {
		return nil
	}
	h := sha256.Sum256([]byte(strings.Join(s.threadIDs(t), ",")))
	return h[:]
}

// TombstoneIDs lists every known tombstone id.
func (s *Store) TombstoneIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tombs))
	for id := range s.tombs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RawTombstones returns the encodings of the requested tombstones.
func (s *Store) RawTombstones(ids []string) [][]byte {
	var out [][]byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTombstones)
		for _, id := range ids {
			if v := b.Get([]byte(id)); v != nil {
				out = append(out, slices.Clone(v))
			}
		}
		return nil
	})
	return out
}

// BlobRefs lists every blob CID referenced by a stored post.
func (s *Store) BlobRefs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.blobRefs))
	for c := range s.blobRefs {
		out = append(out, c)
	}
	return out
}

// Referenced reports whether any stored post points at blob c.
func (s *Store) Referenced(c string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blobRefs[c] > 0
}

// Stats summarises the store for the status page.
type Stats struct {
	Threads, Posts, Tombstones int
}

// Stats returns counts of stored items.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Threads: len(s.threads), Posts: len(s.posts), Tombstones: len(s.tombs)}
}

// Resolve finds a stored post by full id or unique id prefix and returns the
// post id and its thread id.
func (s *Store) Resolve(prefix string) (id, thread string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if pi, found := s.posts[prefix]; found {
		return pi.id, pi.thread, true
	}
	if len(prefix) < 6 {
		return "", "", false
	}
	for pid, pi := range s.posts {
		if strings.HasPrefix(pid, prefix) {
			if ok {
				return "", "", false // ambiguous
			}
			id, thread, ok = pid, pi.thread, true
		}
	}
	return id, thread, ok
}

// ThreadSalt returns the salt of a stored thread opener, needed to sign
// replies to it.
func (s *Store) ThreadSalt(thread string) ([]byte, bool) {
	p, ok := s.Post(thread)
	if !ok || !p.IsOP() {
		return nil, false
	}
	return p.ThreadSalt, true
}
