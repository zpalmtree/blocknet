package main

import (
	"encoding/json"
	"strings"
	"testing"

	"blocknet/protocol/params"
)

func TestJSONUnmarshalOmittedEncryptedMemoIsRejected_NonCoinbase(t *testing.T) {
	// This matches the daemon ingest reality: blocks/txs are JSON unmarshaled into
	// Go structs with fixed-size arrays; omitted fields default to zero arrays.
	//
	// We don't need a fully valid RingCT tx here because memo policy is checked
	// before expensive signature/proof verification.
	txJSON := []byte(`{
	  "version": 1,
	  "tx_public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	  "fee": 0,
	  "inputs": [{}],
	  "outputs": [
	    {
	      "commitment": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	      "public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	      "encrypted_amount": [0,0,0,0,0,0,0,0]
	    }
	  ]
	}`)

	var tx Transaction
	if err := json.Unmarshal(txJSON, &tx); err != nil {
		t.Fatalf("failed to unmarshal tx JSON: %v", err)
	}
	if tx.Outputs[0].EncryptedMemo != ([params.MemoSize]byte{}) {
		t.Fatal("expected omitted encrypted_memo to default to all-zero array")
	}

	err := ValidateTransaction(
		&tx,
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)
	if err == nil {
		t.Fatal("expected tx with omitted encrypted_memo (zero default) to be rejected")
	}
	if !strings.Contains(err.Error(), "encrypted memo must not be all-zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONUnmarshalOmittedEncryptedMemoIsRejected_Coinbase(t *testing.T) {
	txJSON := []byte(`{
	  "version": 1,
	  "tx_public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	  "fee": 0,
	  "inputs": [],
	  "outputs": [
	    {
	      "commitment": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	      "public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	      "encrypted_amount": [0,0,0,0,0,0,0,0]
	    }
	  ]
	}`)

	var tx Transaction
	if err := json.Unmarshal(txJSON, &tx); err != nil {
		t.Fatalf("failed to unmarshal coinbase-like tx JSON: %v", err)
	}

	err := ValidateTransaction(&tx, func(_ [32]byte) bool { return false }, nil)
	if err == nil {
		t.Fatal("expected coinbase with omitted encrypted_memo (zero default) to be rejected")
	}
	if !strings.Contains(err.Error(), "encrypted memo must not be all-zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

