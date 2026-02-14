package main

import (
	"bytes"
	"testing"

	"blocknet/protocol/params"
)

func FuzzDeserializeTx_NoPanicAndCanonicalRoundTrip(f *testing.F) {
	// Minimal header-only tx (0 inputs/0 outputs) at the memo-era wire shape.
	f.Add(make([]byte, 1+32+4+4+8))

	// Header + 1 output (includes fixed memo bytes).
	{
		tx := &Transaction{
			Version:     1,
			TxPublicKey: [32]byte{0x11},
			Fee:         0,
			Inputs:      nil,
			Outputs: []TxOutput{
				{
					PublicKey:       [32]byte{0x22},
					Commitment:      [32]byte{0x33},
					EncryptedAmount: [8]byte{0x44},
					EncryptedMemo:   [params.MemoSize]byte{0x01},
					RangeProof:      nil,
				},
			},
		}
		f.Add(tx.Serialize())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tx1, err1 := DeserializeTx(data)
		tx2, err2 := DeserializeTx(data)

		// Deterministic accept/reject for identical input bytes.
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic parse result: err1=%v err2=%v", err1, err2)
		}
		if err1 != nil {
			return
		}

		// Canonical exact-consumption implies serialization round-trips exactly.
		ser1 := tx1.Serialize()
		ser2 := tx2.Serialize()
		if !bytes.Equal(ser1, data) {
			t.Fatalf("Serialize() did not round-trip input bytes: got %d bytes, want %d", len(ser1), len(data))
		}
		if !bytes.Equal(ser1, ser2) {
			t.Fatal("same input produced different canonical serialization")
		}

		// Re-deserializing canonical bytes must succeed.
		tx3, err := DeserializeTx(ser1)
		if err != nil {
			t.Fatalf("failed to deserialize canonical bytes: %v", err)
		}
		if !bytes.Equal(tx3.Serialize(), ser1) {
			t.Fatal("canonical bytes did not round-trip through deserialize+serialize")
		}
	})
}

