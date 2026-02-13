package main

import (
	"strings"
	"testing"
)

func TestDeserializeTxRejectsTrailingBytes(t *testing.T) {
	tx := &Transaction{
		Version:     1,
		TxPublicKey: [32]byte{0xAA},
		Inputs:      nil,
		Outputs: []TxOutput{
			{
				PublicKey:       [32]byte{0xBB},
				Commitment:      [32]byte{0xCC},
				EncryptedAmount: [8]byte{0x01},
			},
		},
		Fee: 0,
	}

	canonical := tx.Serialize()
	withTrailing := append(append([]byte(nil), canonical...), 0xDE, 0xAD, 0xBE, 0xEF)

	_, err := DeserializeTx(withTrailing)
	if err == nil {
		t.Fatal("expected trailing-byte transaction to be rejected")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

