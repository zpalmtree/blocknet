package p2p

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestPEX_AddKnownPeer_FiltersPrivateAndDocMultiaddrs(t *testing.T) {
	n := mustNewTestNode(t)
	defer func() { _ = n.Stop() }()

	pex := n.pex
	if pex == nil {
		t.Fatal("expected node to have pex")
	}

	pid := peer.ID("test-peer")

	mustMA := func(s string) multiaddr.Multiaddr {
		t.Helper()
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("invalid multiaddr %q: %v", s, err)
		}
		return ma
	}

	addrs := []multiaddr.Multiaddr{
		mustMA("/ip4/127.0.0.1/tcp/28080"),
		mustMA("/ip4/10.0.0.1/tcp/28080"),
		mustMA("/ip4/192.168.1.10/tcp/28080"),
		mustMA("/ip4/100.64.0.1/tcp/28080"),     // CGNAT
		mustMA("/ip4/198.51.100.5/tcp/28080"),   // doc range
		mustMA("/ip4/8.8.8.8/tcp/28080"),        // routable
		mustMA("/ip6/fe80::1/tcp/28080"),        // link-local
		mustMA("/ip6/2001:db8::1/tcp/28080"),    // doc range
		mustMA("/dns4/example.com/tcp/28080"),   // should be rejected (no DNS from PEX)
		mustMA("/ip4/0.0.0.0/tcp/28080"),        // unspecified
		mustMA("/ip4/255.255.255.255/tcp/28080"), // broadcast-ish (non-global)
	}

	pex.addKnownPeer(pid, addrs)

	pex.mu.RLock()
	rec := pex.knownPeers[pid]
	pex.mu.RUnlock()
	if rec == nil {
		t.Fatal("expected peer record to exist (routable addr present)")
	}
	if len(rec.Addrs) != 1 || rec.Addrs[0] != "/ip4/8.8.8.8/tcp/28080" {
		t.Fatalf("expected only routable addr stored, got %v", rec.Addrs)
	}

	// Peerstore should also only contain the routable addr.
	psAddrs := n.host.Peerstore().Addrs(pid)
	psAddrs = filterRoutableAddrs(psAddrs)
	if len(psAddrs) != 1 || psAddrs[0].String() != "/ip4/8.8.8.8/tcp/28080" {
		got := make([]string, 0, len(psAddrs))
		for _, a := range psAddrs {
			got = append(got, a.String())
		}
		t.Fatalf("expected peerstore to have only routable addr, got %v", got)
	}

	// Ensure no private addr slipped into peerstore at all.
	for _, a := range n.host.Peerstore().Addrs(pid) {
		if !isRoutablePEXAddr(a) {
			t.Fatalf("expected peerstore addrs to be routable-only, got %q", a.String())
		}
	}

	// Also ensure the TTL add doesn't keep old state around across updates.
	pex.addKnownPeer(pid, []multiaddr.Multiaddr{mustMA("/ip4/8.8.4.4/tcp/28080")})
	time.Sleep(10 * time.Millisecond) // best-effort, no background required
	pex.mu.RLock()
	rec2 := pex.knownPeers[pid]
	pex.mu.RUnlock()
	if rec2 == nil || len(rec2.Addrs) != 1 || rec2.Addrs[0] != "/ip4/8.8.4.4/tcp/28080" {
		t.Fatalf("expected record addrs to update deterministically, got %v", rec2)
	}
}

