package p2p

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadLengthPrefixedWithLimit_RejectsOversizePayload(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(5)); err != nil {
		t.Fatalf("failed to write length: %v", err)
	}
	buf.Write([]byte("abcde"))

	_, err := readLengthPrefixedWithLimit(&buf, 4)
	if err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
	if !strings.Contains(err.Error(), "message too large: 5 > 4") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadMessageWithLimit_UsesTypeSpecificCap(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x2A)
	if err := binary.Write(&buf, binary.BigEndian, uint32(6)); err != nil {
		t.Fatalf("failed to write length: %v", err)
	}
	buf.Write([]byte("123456"))

	_, _, err := readMessageWithLimit(&buf, func(msgType byte) (uint32, error) {
		if msgType != 0x2A {
			t.Fatalf("unexpected message type: %d", msgType)
		}
		return 4, nil
	})
	if err == nil {
		t.Fatal("expected type-specific cap rejection")
	}
	if !strings.Contains(err.Error(), "message too large: 6 > 4") {
		t.Fatalf("unexpected error: %v", err)
	}
}
