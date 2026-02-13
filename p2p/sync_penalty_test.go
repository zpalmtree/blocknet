package p2p

import (
	"context"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func newPenaltyTestNode() *Node {
	n := &Node{}
	n.pex = NewPeerExchange(n, nil)
	return n
}

func TestHandleNewBlock_PenalizesInvalidAnnouncement(t *testing.T) {
	n := newPenaltyTestNode()
	sm := NewSyncManager(n, SyncConfig{
		ProcessBlock: func(data []byte) error {
			return errors.New("invalid block")
		},
		IsOrphanError:    func(error) bool { return false },
		IsDuplicateError: func(error) bool { return false },
	})

	pid := peer.ID("12D3KooWInvalidAnnouncePeer")
	sm.handleNewBlock(pid, []byte("bad-block"))

	if got := n.BannedCount(); got != 1 {
		t.Fatalf("expected invalid announcement peer to be banned, bannedCount=%d", got)
	}
}

func TestHandleNewBlock_DoesNotPenalizeOrphanOrDuplicate(t *testing.T) {
	t.Run("orphan", func(t *testing.T) {
		n := newPenaltyTestNode()
		orph := errors.New("orphan")
		sm := NewSyncManager(n, SyncConfig{
			ProcessBlock:      func(data []byte) error { return orph },
			IsOrphanError:     func(err error) bool { return errors.Is(err, orph) },
			IsDuplicateError:  func(error) bool { return false },
		})
		sm.handleNewBlock(peer.ID("12D3KooWOrphanPeer000001"), []byte("orphan"))
		if got := n.BannedCount(); got != 0 {
			t.Fatalf("orphan announcement should not be penalized, bannedCount=%d", got)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		n := newPenaltyTestNode()
		dup := errors.New("duplicate")
		sm := NewSyncManager(n, SyncConfig{
			ProcessBlock:      func(data []byte) error { return dup },
			IsOrphanError:     func(error) bool { return false },
			IsDuplicateError:  func(err error) bool { return errors.Is(err, dup) },
		})
		sm.handleNewBlock(peer.ID("12D3KooWDuplicatePeer0001"), []byte("dup"))
		if got := n.BannedCount(); got != 0 {
			t.Fatalf("duplicate announcement should not be penalized, bannedCount=%d", got)
		}
	})
}

func TestFetchBlockByHashFromAnyPeer_PenalizesEmptyUndecodableAndMismatched(t *testing.T) {
	targetHash := [32]byte{0xAA}
	pid := peer.ID("12D3KooWFetchPenaltyPeer01")
	peers := []PeerStatus{{Peer: pid}}

	t.Run("empty response", func(t *testing.T) {
		n := newPenaltyTestNode()
		sm := &SyncManager{
			node: n,
			fetchBlocksByHash: func(context.Context, peer.ID, [][32]byte) ([][]byte, error) {
				return [][]byte{}, nil
			},
			getBlockHash: func(data []byte) ([32]byte, error) {
				return [32]byte{}, nil
			},
		}

		_, _, err := sm.fetchBlockByHashFromAnyPeer(context.Background(), peers, targetHash, nil)
		if err == nil {
			t.Fatal("expected error from empty block response")
		}
		if got := n.BannedCount(); got != 1 {
			t.Fatalf("expected empty response peer penalty, bannedCount=%d", got)
		}
	})

	t.Run("undecodable response", func(t *testing.T) {
		n := newPenaltyTestNode()
		sm := &SyncManager{
			node: n,
			fetchBlocksByHash: func(context.Context, peer.ID, [][32]byte) ([][]byte, error) {
				return [][]byte{[]byte("not-a-block")}, nil
			},
			getBlockHash: func(data []byte) ([32]byte, error) {
				return [32]byte{}, errors.New("decode failed")
			},
		}

		_, _, err := sm.fetchBlockByHashFromAnyPeer(context.Background(), peers, targetHash, nil)
		if err == nil {
			t.Fatal("expected error from undecodable block response")
		}
		if got := n.BannedCount(); got != 1 {
			t.Fatalf("expected undecodable response peer penalty, bannedCount=%d", got)
		}
	})

	t.Run("mismatched hash response", func(t *testing.T) {
		n := newPenaltyTestNode()
		sm := &SyncManager{
			node: n,
			fetchBlocksByHash: func(context.Context, peer.ID, [][32]byte) ([][]byte, error) {
				return [][]byte{[]byte("fake-block")}, nil
			},
			getBlockHash: func(data []byte) ([32]byte, error) {
				return [32]byte{0xBB}, nil // deliberately mismatched
			},
		}

		_, _, err := sm.fetchBlockByHashFromAnyPeer(context.Background(), peers, targetHash, nil)
		if err == nil {
			t.Fatal("expected error from mismatched hash response")
		}
		if got := n.BannedCount(); got != 1 {
			t.Fatalf("expected mismatched-hash response peer penalty, bannedCount=%d", got)
		}
	})
}
