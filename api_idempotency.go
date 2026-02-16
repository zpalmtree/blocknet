package main

import (
	"crypto/sha256"
	"sync"
	"time"
)

type idempotencyResult struct {
	status int
	body   []byte
}

type idempotencyCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]*idempotencyEntry
}

type idempotencyEntry struct {
	createdAt time.Time
	reqHash   [32]byte
	inFlight  bool
	result    idempotencyResult
}

func newIdempotencyCache(ttl time.Duration, maxEntries int) *idempotencyCache {
	return &idempotencyCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]*idempotencyEntry),
	}
}

func (c *idempotencyCache) getOrStart(now time.Time, key string, reqHash [32]byte) (state string, res idempotencyResult) {
	// state:
	// - "replay": res is valid
	// - "start": caller should process request and then complete()
	// - "inflight": same key currently running
	// - "mismatch": key exists but request differs
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)

	if e, ok := c.entries[key]; ok {
		if e.reqHash != reqHash {
			return "mismatch", idempotencyResult{}
		}
		if e.inFlight {
			return "inflight", idempotencyResult{}
		}
		return "replay", e.result
	}

	c.entries[key] = &idempotencyEntry{
		createdAt: now,
		reqHash:   reqHash,
		inFlight:  true,
	}
	c.enforceCapLocked()
	return "start", idempotencyResult{}
}

func (c *idempotencyCache) complete(now time.Time, key string, reqHash [32]byte, status int, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)

	e, ok := c.entries[key]
	if !ok {
		return
	}
	if e.reqHash != reqHash {
		// If the key was somehow reused with a different request, don't cache a response.
		delete(c.entries, key)
		return
	}
	e.createdAt = now
	e.inFlight = false
	e.result = idempotencyResult{status: status, body: append([]byte(nil), body...)}
	c.enforceCapLocked()
}

func (c *idempotencyCache) abandon(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *idempotencyCache) pruneLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	for k, e := range c.entries {
		// Never expire in-flight entries; dropping them re-allows duplicate processing.
		if e.inFlight {
			continue
		}
		if now.Sub(e.createdAt) > c.ttl {
			delete(c.entries, k)
		}
	}
}

func (c *idempotencyCache) enforceCapLocked() {
	if c.maxEntries <= 0 || len(c.entries) <= c.maxEntries {
		return
	}

	// Evict oldest completed entries first.
	// Never evict in-flight entries; callers use those to prevent duplicate processing.
	for len(c.entries) > c.maxEntries {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, e := range c.entries {
			if e.inFlight {
				continue
			}
			if first || e.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.createdAt
				first = false
			}
		}
		if oldestKey == "" {
			// All remaining entries are in-flight; keep them even if we're over cap.
			return
		}
		delete(c.entries, oldestKey)
	}
}

func hashRequestBody(body []byte) [32]byte {
	return sha256.Sum256(body)
}

