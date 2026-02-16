package main

import (
	"testing"
	"time"
)

func TestIdempotencyCapNeverEvictsInFlight(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newIdempotencyCache(10*time.Minute, 1)

	var h1, h2 [32]byte
	h1[0] = 1
	h2[0] = 2

	state, _ := c.getOrStart(now, "k1", h1)
	if state != "start" {
		t.Fatalf("expected start for k1, got %q", state)
	}
	state, _ = c.getOrStart(now.Add(1*time.Second), "k2", h2)
	if state != "start" {
		t.Fatalf("expected start for k2, got %q", state)
	}

	c.mu.Lock()
	if len(c.entries) != 2 {
		c.mu.Unlock()
		t.Fatalf("expected 2 entries (over cap due to in-flight protection), got %d", len(c.entries))
	}
	if !c.entries["k1"].inFlight || !c.entries["k2"].inFlight {
		c.mu.Unlock()
		t.Fatalf("expected both entries to be in-flight")
	}
	c.mu.Unlock()

	// Completing one request makes it eligible for eviction; cap should drop back to 1.
	c.complete(now.Add(2*time.Second), "k1", h1, 200, []byte(`{"ok":true}`))

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 1 {
		t.Fatalf("expected 1 entry after completion + cap enforcement, got %d", len(c.entries))
	}
	if _, ok := c.entries["k2"]; !ok || !c.entries["k2"].inFlight {
		t.Fatalf("expected remaining entry to be k2 in-flight")
	}
}

func TestIdempotencyPruneSkipsInFlight(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newIdempotencyCache(1*time.Second, 100)

	var h [32]byte
	h[0] = 9

	_, _ = c.getOrStart(now, "k", h)

	// Advance beyond TTL; prune should not remove in-flight entry.
	c.mu.Lock()
	c.pruneLocked(now.Add(10 * time.Second))
	_, ok := c.entries["k"]
	c.mu.Unlock()

	if !ok {
		t.Fatal("expected in-flight entry to survive prune")
	}
}

