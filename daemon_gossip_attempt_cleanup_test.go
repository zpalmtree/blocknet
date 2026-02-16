package main

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestGossipBlockAttemptTracker_PurgesStaleEntriesOnAcquire(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	// Use a small-ish cap for the test so we can reason about sizes, while still
	// allowing both stale + recent entries to coexist before purge.
	d.gossipBlockLastAttempt = newGossipAttemptLRU(512)

	now := time.Now()
	staleTime := now.Add(-gossipBlockAttemptTTL - 1*time.Minute)
	recentTime := now.Add(-1 * time.Minute)

	var stalePIDs []peer.ID
	for i := 0; i < 200; i++ {
		pid := peer.ID("stale-peer-" + itoa(i))
		stalePIDs = append(stalePIDs, pid)
		d.gossipBlockLastAttempt.Set(pid, staleTime)
	}

	var recentPIDs []peer.ID
	for i := 0; i < 5; i++ {
		pid := peer.ID("recent-peer-" + itoa(i))
		recentPIDs = append(recentPIDs, pid)
		d.gossipBlockLastAttempt.Set(pid, recentTime)
	}

	// Sanity: everything is present pre-purge.
	if got := d.gossipBlockLastAttempt.lru.Len(); got != len(stalePIDs)+len(recentPIDs) {
		t.Fatalf("unexpected pre-purge LRU size: got %d, want %d", got, len(stalePIDs)+len(recentPIDs))
	}

	triggerPID := peer.ID("trigger-peer")
	if err := d.acquireGossipBlockValidationSlot(triggerPID); err != nil {
		t.Fatalf("acquire slot failed: %v", err)
	}
	d.releaseGossipBlockValidationSlot()

	// Stale entries should be purged.
	for _, pid := range stalePIDs {
		if _, ok := d.gossipBlockLastAttempt.Get(pid); ok {
			t.Fatalf("expected stale pid %q to be purged", string(pid))
		}
	}

	// Recent entries should remain.
	for _, pid := range recentPIDs {
		if _, ok := d.gossipBlockLastAttempt.Get(pid); !ok {
			t.Fatalf("expected recent pid %q to remain after purge", string(pid))
		}
	}

	// Trigger PID should be recorded as an attempt too.
	if _, ok := d.gossipBlockLastAttempt.Get(triggerPID); !ok {
		t.Fatalf("expected trigger pid %q to exist after acquire", string(triggerPID))
	}

	// Post-purge size should be bounded to recent + trigger (order may change).
	if got := d.gossipBlockLastAttempt.lru.Len(); got != len(recentPIDs)+1 {
		t.Fatalf("unexpected post-purge LRU size: got %d, want %d", got, len(recentPIDs)+1)
	}
	if got := len(d.gossipBlockLastAttempt.index); got != len(recentPIDs)+1 {
		t.Fatalf("unexpected post-purge index size: got %d, want %d", got, len(recentPIDs)+1)
	}
}

func TestGossipBlockAttemptTracker_CapBoundsPeerIDChurn(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	cap := 64
	d.gossipBlockLastAttempt = newGossipAttemptLRU(cap)

	now := time.Now()
	for i := 0; i < 1000; i++ {
		d.gossipBlockLastAttempt.Set(peer.ID("churn-peer-"+itoa(i)), now)
	}

	if got := d.gossipBlockLastAttempt.lru.Len(); got != cap {
		t.Fatalf("unexpected LRU size after churn: got %d, want %d", got, cap)
	}
	if got := len(d.gossipBlockLastAttempt.index); got != cap {
		t.Fatalf("unexpected index size after churn: got %d, want %d", got, cap)
	}
}

func itoa(v int) string {
	// Avoid pulling in strconv for test-only strings.
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var buf [32]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

