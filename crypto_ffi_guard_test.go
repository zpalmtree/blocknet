package main

import (
	"strings"
	"testing"
)

func TestVerifyRangeProofRejectsEmptyProof(t *testing.T) {
	err := VerifyRangeProof([32]byte{}, &RangeProof{Proof: nil})
	if err == nil {
		t.Fatal("expected empty range proof to be rejected")
	}
	if !strings.Contains(err.Error(), "range proof must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyRingRejectsEmptySignature(t *testing.T) {
	ring := [][32]byte{{}}
	err := VerifyRing(ring, []byte("msg"), &RingSignature{
		RingSize:  1,
		Signature: nil,
	})
	if err == nil {
		t.Fatal("expected empty ring signature to be rejected")
	}
	if !strings.Contains(err.Error(), "ring signature must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTransactionRejectsEmptyRingCTSignature(t *testing.T) {
	txData := mustCraftMalformedTxVariant(t, "empty-ringct-signature")
	tx, err := DeserializeTx(txData)
	if err != nil {
		t.Fatalf("failed to deserialize malformed tx variant: %v", err)
	}

	err = ValidateTransaction(
		tx,
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)
	if err == nil {
		t.Fatal("expected transaction with empty RingCT signature to be rejected")
	}
	if !strings.Contains(err.Error(), "RingCT signature must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}
