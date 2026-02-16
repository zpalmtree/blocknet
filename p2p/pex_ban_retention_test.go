package p2p

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestEnforceBanRetentionCapsPermanentBans(t *testing.T) {
	pex := &PeerExchange{
		knownPeers:   make(map[peer.ID]*PeerRecord),
		bannedPeers:  make(map[peer.ID]*BanRecord),
		lastExchange: make(map[peer.ID]time.Time),
	}

	now := time.Unix(1_700_000_000, 0)

	// Insert more than MaxPermanentBans with deterministic timestamps so eviction is deterministic.
	for i := 0; i < MaxPermanentBans+10; i++ {
		pid := peer.ID(fmt.Sprintf("peer-%d", i))
		pex.bannedPeers[pid] = &BanRecord{
			PeerID:     pid,
			Reason:     "test",
			BannedAt:   now.Add(time.Duration(i) * time.Second),
			ExpiresAt:  now.Add(24 * time.Hour),
			BanCount:   MaxBansBeforePermanent,
			Permanent:  true,
		}
	}

	pex.enforceBanRetentionLocked(now)

	permanentCount := 0
	for _, ban := range pex.bannedPeers {
		if ban.Permanent {
			permanentCount++
		}
	}
	if permanentCount != MaxPermanentBans {
		t.Fatalf("expected permanent bans capped at %d, got %d", MaxPermanentBans, permanentCount)
	}
}

func TestEnforceBanRetentionAgesOutPermanentBans(t *testing.T) {
	pex := &PeerExchange{
		knownPeers:   make(map[peer.ID]*PeerRecord),
		bannedPeers:  make(map[peer.ID]*BanRecord),
		lastExchange: make(map[peer.ID]time.Time),
	}

	now := time.Unix(1_700_000_000, 0)
	old := now.Add(-PermanentBanRetention - time.Hour)

	pidOld := peer.ID("old-peer")
	pex.bannedPeers[pidOld] = &BanRecord{
		PeerID:    pidOld,
		Reason:    "test",
		BannedAt:  old,
		ExpiresAt: old.Add(24 * time.Hour),
		BanCount:  MaxBansBeforePermanent,
		Permanent: true,
	}
	pidNew := peer.ID("new-peer")
	pex.bannedPeers[pidNew] = &BanRecord{
		PeerID:    pidNew,
		Reason:    "test",
		BannedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		BanCount:  MaxBansBeforePermanent,
		Permanent: true,
	}

	pex.enforceBanRetentionLocked(now)

	if _, ok := pex.bannedPeers[pidOld]; ok {
		t.Fatal("expected old permanent ban to be aged out")
	}
	if _, ok := pex.bannedPeers[pidNew]; !ok {
		t.Fatal("expected new permanent ban to remain")
	}
}

