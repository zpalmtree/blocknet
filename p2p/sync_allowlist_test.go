package p2p

import (
	"context"
	"sync/atomic"
	"testing"

	"blocknet/protocol/params"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestCheckSync_OnlyQueriesAllowedPeers(t *testing.T) {
	a := mustNewTestNode(t)
	defer func() { _ = a.Stop() }()
	b := mustNewTestNode(t)
	defer func() { _ = b.Stop() }()
	c := mustNewTestNode(t)
	defer func() { _ = c.Stop() }()

	mustConnectNodes(t, a, b)
	mustConnectNodes(t, a, c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	our := ChainStatus{Height: 10, TotalWork: 100, Version: 1, NetworkID: params.NetworkID, ChainID: params.ChainID}

	smA := NewSyncManager(a, SyncConfig{
		GetStatus:        func() ChainStatus { return our },
		AllowedSyncPeers: []peer.ID{b.PeerID()},
	})
	smA.ctx, smA.cancel = context.WithCancel(ctx)

	smB := NewSyncManager(b, SyncConfig{
		GetStatus: func() ChainStatus { return our },
	})
	smB.ctx, smB.cancel = context.WithCancel(ctx)

	smC := NewSyncManager(c, SyncConfig{
		GetStatus: func() ChainStatus { return our },
	})
	smC.ctx, smC.cancel = context.WithCancel(ctx)

	var bRequests atomic.Int64
	b.host.SetStreamHandler(protocolID(params.ProtocolSync), func(s network.Stream) {
		bRequests.Add(1)
		smB.HandleStream(s)
	})

	var cRequests atomic.Int64
	c.host.SetStreamHandler(protocolID(params.ProtocolSync), func(s network.Stream) {
		cRequests.Add(1)
		smC.HandleStream(s)
	})

	smA.checkSync()

	if got := bRequests.Load(); got != 1 {
		t.Fatalf("expected allowed peer to receive exactly one status request, got %d", got)
	}
	if got := cRequests.Load(); got != 0 {
		t.Fatalf("expected disallowed peer to receive no status requests, got %d", got)
	}
}
