package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

type recoveryTestBlock struct {
	Height uint64   `json:"height"`
	Hash   [32]byte `json:"hash"`
	Prev   [32]byte `json:"prev"`
}

func encodeRecoveryBlock(t *testing.T, b recoveryTestBlock) []byte {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("failed to marshal recovery block: %v", err)
	}
	return data
}

func TestProcessBlockWithRecoveryCtx_OrphanBackfillReconnectsChain(t *testing.T) {
	errOrphan := errors.New("orphan")
	parentHash := [32]byte{0xAA}
	childHash := [32]byte{0xBB}

	parentData := encodeRecoveryBlock(t, recoveryTestBlock{
		Height: 10,
		Hash:   parentHash,
		Prev:   [32]byte{0x09},
	})
	childData := encodeRecoveryBlock(t, recoveryTestBlock{
		Height: 11,
		Hash:   childHash,
		Prev:   parentHash,
	})

	parentAccepted := false
	childAccepted := false

	sm := NewSyncManager(newPenaltyTestNode(), SyncConfig{
		ProcessBlock: func(data []byte) error {
			var b recoveryTestBlock
			if err := json.Unmarshal(data, &b); err != nil {
				return err
			}
			switch b.Hash {
			case childHash:
				if !parentAccepted {
					return errOrphan
				}
				childAccepted = true
				return nil
			case parentHash:
				parentAccepted = true
				return nil
			default:
				return nil
			}
		},
		IsOrphanError:    func(err error) bool { return errors.Is(err, errOrphan) },
		IsDuplicateError: func(error) bool { return false },
		GetBlockMeta: func(data []byte) (uint64, [32]byte, error) {
			var b recoveryTestBlock
			if err := json.Unmarshal(data, &b); err != nil {
				return 0, [32]byte{}, err
			}
			return b.Height, b.Prev, nil
		},
		GetBlockHash: func(data []byte) ([32]byte, error) {
			var b recoveryTestBlock
			if err := json.Unmarshal(data, &b); err != nil {
				return [32]byte{}, err
			}
			return b.Hash, nil
		},
		FetchBlocksByHash: func(ctx context.Context, p peer.ID, hashes [][32]byte) ([][]byte, error) {
			if len(hashes) == 1 && hashes[0] == parentHash {
				return [][]byte{parentData}, nil
			}
			return nil, errors.New("unexpected hash request")
		},
	})

	peers := []PeerStatus{{Peer: peer.ID("12D3KooWRecoveryPeer00001")}}
	if err := sm.ProcessBlockWithRecoveryCtx(context.Background(), childData, peers); err != nil {
		t.Fatalf("expected orphan recovery to succeed, got: %v", err)
	}
	if !parentAccepted {
		t.Fatal("expected parent block to be fetched and accepted during recovery")
	}
	if !childAccepted {
		t.Fatal("expected orphan child to be replayed and accepted after parent recovery")
	}
}
