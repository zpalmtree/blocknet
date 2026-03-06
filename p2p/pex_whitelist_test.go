package p2p

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const testWhitelistPeerID = "12D3KooWQUNGJrsU5nRXNk45FT3ZumdtWC9Sg9Xt2AgU3XkP382R"

func mustDecodePeerID(t *testing.T, raw string) peer.ID {
	t.Helper()
	pid, err := peer.Decode(raw)
	if err != nil {
		t.Fatalf("failed to decode peer ID %q: %v", raw, err)
	}
	return pid
}

func TestNewPeerIDSetRejectsInvalidPeerID(t *testing.T) {
	if _, err := newPeerIDSet([]string{"not-a-peer-id"}); err == nil {
		t.Fatal("expected invalid peer ID to be rejected")
	}
}

func TestPeerExchange_WhitelistedPeerCannotBeBanned(t *testing.T) {
	pid := mustDecodePeerID(t, testWhitelistPeerID)
	pex := NewPeerExchange(&Node{}, nil, map[peer.ID]struct{}{pid: {}})

	pex.BanPeer(pid, "test ban", BanDurationMedium)
	if pex.IsBanned(pid) {
		t.Fatal("expected whitelisted peer to remain unbanned")
	}
	if got := pex.BannedPeerCount(); got != 0 {
		t.Fatalf("expected no active bans, got %d", got)
	}
}

func TestPeerExchange_WhitelistedPeerCannotBeScoreBanned(t *testing.T) {
	pid := mustDecodePeerID(t, testWhitelistPeerID)
	pex := NewPeerExchange(&Node{}, nil, map[peer.ID]struct{}{pid: {}})
	pex.knownPeers[pid] = &PeerRecord{
		ID:       pid.String(),
		Score:    1,
		LastSeen: time.Now().Unix(),
	}

	pex.PenalizePeer(pid, -1, "score exhausted")
	if pex.IsBanned(pid) {
		t.Fatal("expected whitelisted peer to ignore score-triggered ban")
	}
	if got := pex.GetPeerScore(pid); got != 0 {
		t.Fatalf("expected score to drop to zero without a ban, got %d", got)
	}
}

func TestPeerExchange_WhitelistHidesExistingBanRecords(t *testing.T) {
	pid := mustDecodePeerID(t, testWhitelistPeerID)
	pex := NewPeerExchange(&Node{}, nil, map[peer.ID]struct{}{pid: {}})
	pex.bannedPeers[pid] = &BanRecord{
		PeerID:    pid,
		Reason:    "test",
		BannedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		BanCount:  1,
	}

	if pex.IsBanned(pid) {
		t.Fatal("expected whitelist to override existing ban records")
	}
	if bans := pex.GetBannedPeers(); len(bans) != 0 {
		t.Fatalf("expected whitelisted ban records to be hidden, got %d", len(bans))
	}
	if got := pex.BannedPeerCount(); got != 0 {
		t.Fatalf("expected whitelisted ban record to be excluded from count, got %d", got)
	}
}
