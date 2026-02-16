package main

import (
	"runtime"
	"testing"
)

func TestMinerSetThreads_ClampsToNumCPUAndMinimumOne(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	m := NewMiner(chain, nil, MinerConfig{Threads: 1})

	m.SetThreads(0)
	if got := m.Threads(); got != 1 {
		t.Fatalf("expected threads to clamp to 1, got %d", got)
	}

	max := runtime.NumCPU()
	if max < 1 {
		max = 1
	}
	m.SetThreads(max + 1000)
	if got := m.Threads(); got != max {
		t.Fatalf("expected threads to clamp to NumCPU=%d, got %d", max, got)
	}
}

