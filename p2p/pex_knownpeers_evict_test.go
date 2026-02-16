package p2p

import (
	"strconv"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestPEX_EvictKnownPeers_DeterministicAndClearsPeerstoreAddrs(t *testing.T) {
	n := mustNewTestNode(t)
	defer func() { _ = n.Stop() }()

	pex := n.pex
	if pex == nil {
		t.Fatal("expected node to have pex")
	}

	mustMA := func(s string) multiaddr.Multiaddr {
		t.Helper()
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("invalid multiaddr %q: %v", s, err)
		}
		return ma
	}

	// Five non-connected peers; cap to 3.
	// Victim selection: lowest score, then oldest lastSeen, then lexicographic peer ID.
	peers := []struct {
		pid      peer.ID
		score    int
		lastSeen int64
		port     int
	}{
		{pid: peer.ID("peer0"), score: 1, lastSeen: 90, port: 1000},  // tie victim (lexicographically smallest)
		{pid: peer.ID("peer2"), score: 1, lastSeen: 90, port: 1002},  // tie victim (2nd)
		{pid: peer.ID("peer1"), score: 1, lastSeen: 100, port: 1001}, // same score, newer => keep
		{pid: peer.ID("peer3"), score: 2, lastSeen: 80, port: 1003},  // higher score => keep
		{pid: peer.ID("peer4"), score: 3, lastSeen: 70, port: 1004},  // higher score => keep
	}

	pex.mu.Lock()
	for _, p := range peers {
		ma := mustMA("/ip4/8.8.8.8/tcp/" + strconv.Itoa(p.port))
		// Pre-populate peerstore so eviction can prove ClearAddrs().
		n.host.Peerstore().AddAddrs(p.pid, []multiaddr.Multiaddr{ma}, time.Hour)

		pex.knownPeers[p.pid] = &PeerRecord{
			ID:       p.pid.String(),
			Addrs:    []string{ma.String()},
			LastSeen: p.lastSeen,
			Score:    p.score,
		}
	}

	pex.evictKnownPeersLocked(3)
	pex.mu.Unlock()

	pex.mu.RLock()
	_, hasPeer0 := pex.knownPeers[peer.ID("peer0")]
	_, hasPeer2 := pex.knownPeers[peer.ID("peer2")]
	_, hasPeer1 := pex.knownPeers[peer.ID("peer1")]
	_, hasPeer3 := pex.knownPeers[peer.ID("peer3")]
	_, hasPeer4 := pex.knownPeers[peer.ID("peer4")]
	gotCount := len(pex.knownPeers)
	pex.mu.RUnlock()

	if gotCount != 3 {
		t.Fatalf("expected final knownPeers size 3, got %d", gotCount)
	}
	if hasPeer0 || hasPeer2 {
		t.Fatalf("expected peer0 and peer2 to be evicted (peer0=%v peer2=%v)", hasPeer0, hasPeer2)
	}
	if !hasPeer1 || !hasPeer3 || !hasPeer4 {
		t.Fatalf("expected peer1/peer3/peer4 to remain (peer1=%v peer3=%v peer4=%v)", hasPeer1, hasPeer3, hasPeer4)
	}

	// Evicted peers should have their peerstore addrs cleared.
	if got := n.host.Peerstore().Addrs(peer.ID("peer0")); len(got) != 0 {
		t.Fatalf("expected peerstore addrs cleared for peer0, got %v", got)
	}
	if got := n.host.Peerstore().Addrs(peer.ID("peer2")); len(got) != 0 {
		t.Fatalf("expected peerstore addrs cleared for peer2, got %v", got)
	}
	// Remaining peers should still have at least one addr.
	if got := n.host.Peerstore().Addrs(peer.ID("peer1")); len(got) == 0 {
		t.Fatalf("expected peerstore addrs to remain for peer1")
	}
}

