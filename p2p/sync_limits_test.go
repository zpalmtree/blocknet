package p2p

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnsureJSONArrayMaxItems_RejectsOversizedArray(t *testing.T) {
	data, err := json.Marshal([][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	})
	if err != nil {
		t.Fatalf("failed to marshal test payload: %v", err)
	}

	err = ensureJSONArrayMaxItems(data, 2)
	if err == nil {
		t.Fatal("expected oversized array to be rejected")
	}
	if !strings.Contains(err.Error(), "array contains 3 items (max 2)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrimByteSliceBatch_EnforcesItemAndByteCaps(t *testing.T) {
	items := [][]byte{
		[]byte("aa"),   // 2
		[]byte("bbb"),  // 3
		[]byte("cccc"), // 4
	}

	trimmed := trimByteSliceBatch(items, 2, 4)
	if len(trimmed) != 1 {
		t.Fatalf("expected 1 item after trim, got %d", len(trimmed))
	}
	if string(trimmed[0]) != "aa" {
		t.Fatalf("unexpected first item kept: %q", string(trimmed[0]))
	}
}
