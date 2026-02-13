package p2p

import "testing"

func TestComputeSyncStartHeight_UsesNearTipOverlap(t *testing.T) {
	if got := computeSyncStartHeight(100, 120); got != 90 {
		t.Fatalf("expected near-tip overlap start at 90, got %d", got)
	}
}

func TestComputeSyncStartHeight_UsesStraightStartWhenFar(t *testing.T) {
	if got := computeSyncStartHeight(100, 200); got != 101 {
		t.Fatalf("expected far-tip start at 101, got %d", got)
	}
}

func TestComputeSyncStartHeight_NoOverlapWhenChainTooShort(t *testing.T) {
	if got := computeSyncStartHeight(10, 30); got != 11 {
		t.Fatalf("expected short-chain start at 11, got %d", got)
	}
}
