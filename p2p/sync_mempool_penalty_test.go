package p2p

import "testing"

func TestMempoolInvalidPenalty(t *testing.T) {
	// Small sample should not penalize even if all invalid.
	if _, _, ok := mempoolInvalidPenalty(10, 10); ok {
		t.Fatal("expected no penalty for small sample")
	}

	// Low invalid ratio should not penalize.
	if _, _, ok := mempoolInvalidPenalty(100, 10); ok {
		t.Fatal("expected no penalty for low invalid ratio")
	}

	// Moderate penalty threshold.
	pen, _, ok := mempoolInvalidPenalty(100, 35)
	if !ok || pen != ScorePenaltyInvalid {
		t.Fatalf("expected ScorePenaltyInvalid, got ok=%v pen=%d", ok, pen)
	}

	// Severe penalty threshold.
	pen, _, ok = mempoolInvalidPenalty(100, 90)
	if !ok || pen != ScorePenaltyMisbehave {
		t.Fatalf("expected ScorePenaltyMisbehave, got ok=%v pen=%d", ok, pen)
	}
}

