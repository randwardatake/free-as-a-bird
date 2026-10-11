package node

import (
	"context"
	"errors"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/randwardatake/free-as-a-bird/internal/board"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
)

// joinTopics subscribes to the manifest, tombstone and per-board topics.
// It is safe to call again after a manifest update adds boards.
func (n *Node) joinTopics() error {
	n.topicMu.Lock()
	defer n.topicMu.Unlock()
	want := map[string]pubsub.ValidatorEx{
		n.topicName("manifest"):   n.validateManifest,
		n.topicName("tombstones"): n.validateTombstone,
	}
	for _, b := range n.Manifest().Payload.Boards {
		want[n.topicName("board/"+b.ID)] = n.validatePost
	}
	for name, val := range want {
		if _, ok := n.topics[name]; ok {
			continue
		}
		if err := n.ps.RegisterTopicValidator(name, val); err != nil {
			return err
		}
		t, err := n.ps.Join(name)
		if err != nil {
			return err
		}
		sub, err := t.Subscribe()
		if err != nil {
			return err
		}
		n.topics[name] = t
		// Validators do the real work; the subscription only has to be
		// drained so that we stay in the mesh.
		n.goLoop(func() {
			for {
				if _, err := sub.Next(n.ctx); err != nil {
					return
				}
			}
		})
	}
	return nil
}

func (n *Node) topic(name string) (*pubsub.Topic, bool) {
	n.topicMu.Lock()
	defer n.topicMu.Unlock()
	t, ok := n.topics[n.topicName(name)]
	return t, ok
}

func (n *Node) validatePost(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	p, err := board.ParsePost(msg.Data)
	if err != nil {
		return pubsub.ValidationReject
	}
	if msg.GetTopic() != n.topicName("board/"+p.Board) {
		return pubsub.ValidationReject
	}
	if from == n.host.ID() {
		return pubsub.ValidationAccept // stored by Publish before gossiping
	}
	res, err := n.Store.Add(p, time.Now())
	n.freeBlobs(res.Freed)
	switch {
	case errors.Is(err, board.ErrDeleted), errors.Is(err, board.ErrPruned), errors.Is(err, board.ErrThreadFull):
		return pubsub.ValidationIgnore
	case err != nil:
		n.log.Debug("rejected post", "from", from, "err", err)
		return pubsub.ValidationReject
	case !res.Added:
		return pubsub.ValidationIgnore
	}
	n.wantImages(p, msg.ReceivedFrom)
	return pubsub.ValidationAccept
}

func (n *Node) validateTombstone(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	t, err := board.ParseTombstone(msg.Data)
	if err != nil {
		return pubsub.ValidationReject
	}
	if from == n.host.ID() {
		return pubsub.ValidationAccept
	}
	res, err := n.Store.AddTombstone(t)
	if err != nil {
		return pubsub.ValidationReject
	}
	n.freeBlobs(res.Freed)
	if !res.Added {
		return pubsub.ValidationIgnore
	}
	return pubsub.ValidationAccept
}

func (n *Node) validateManifest(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	if from == n.host.ID() {
		return pubsub.ValidationAccept
	}
	err := n.AcceptManifest(msg.Data)
	switch {
	case err == nil:
		return pubsub.ValidationAccept
	case errors.Is(err, manifest.ErrNotNewer):
		return pubsub.ValidationIgnore
	default:
		return pubsub.ValidationReject
	}
}

// PublishPost stores a sealed post locally (its blobs must already be in
// the blob store) and gossips it to the network.
func (n *Node) PublishPost(ctx context.Context, p *board.Post) error {
	res, err := n.Store.Add(p, time.Now())
	n.freeBlobs(res.Freed)
	if err != nil {
		return err
	}
	t, ok := n.topic("board/" + p.Board)
	if !ok {
		return errors.New("not subscribed to board " + p.Board)
	}
	return t.Publish(ctx, p.Encode())
}

// PublishTombstone applies a moderator deletion locally and gossips it.
func (n *Node) PublishTombstone(ctx context.Context, t *board.Tombstone) error {
	res, err := n.Store.AddTombstone(t)
	if err != nil {
		return err
	}
	n.freeBlobs(res.Freed)
	topic, ok := n.topic("tombstones")
	if !ok {
		return errors.New("not subscribed to tombstones")
	}
	return topic.Publish(ctx, t.Encode())
}

// PublishManifest accepts a manifest update locally and gossips it.
func (n *Node) PublishManifest(ctx context.Context, raw []byte) error {
	if err := n.AcceptManifest(raw); err != nil {
		return err
	}
	t, ok := n.topic("manifest")
	if !ok {
		return errors.New("not subscribed to manifest topic")
	}
	return t.Publish(ctx, n.Manifest().Marshal())
}
