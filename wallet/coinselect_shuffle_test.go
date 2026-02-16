package wallet

import "testing"

func TestRandomShufflePreservesElements(t *testing.T) {
	outs := []*OwnedOutput{
		{Amount: 1},
		{Amount: 2},
		{Amount: 3},
		{Amount: 4},
		{Amount: 5},
	}

	// Count pointers before shuffle.
	before := make(map[*OwnedOutput]int, len(outs))
	for _, o := range outs {
		before[o]++
	}

	RandomShuffle(outs)

	after := make(map[*OwnedOutput]int, len(outs))
	for _, o := range outs {
		after[o]++
	}

	if len(before) != len(after) {
		t.Fatalf("element set changed: before=%d after=%d", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("element multiplicity changed")
		}
	}
}

