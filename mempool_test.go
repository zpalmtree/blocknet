package main

import (
	"strings"
	"testing"
)

func TestMempoolRejectsCoinbaseTransaction(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	keys, err := GenerateStealthKeys()
	if err != nil {
		t.Fatalf("failed to generate stealth keys: %v", err)
	}

	coinbase, err := CreateCoinbase(keys.SpendPubKey, keys.ViewPubKey, GetBlockReward(1), 1)
	if err != nil {
		t.Fatalf("failed to create coinbase tx: %v", err)
	}

	mempool := NewMempool(DefaultMempoolConfig(), chain.IsKeyImageSpent, chain.IsCanonicalRingMember)
	err = mempool.AddTransaction(coinbase.Tx, coinbase.Tx.Serialize())
	if err == nil {
		t.Fatal("expected coinbase transaction to be rejected by mempool")
	}
	if !strings.Contains(err.Error(), "coinbase transaction cannot be added to mempool") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mempool.Size(); got != 0 {
		t.Fatalf("mempool should remain empty, size=%d", got)
	}
}

func TestMempoolRejectsTamperedRingCTExternalKeyImage(t *testing.T) {
	tx := mustBuildValidRingCTBindingTestTx(t)
	tx.Inputs[0].KeyImage[0] ^= 0x01

	mempool := NewMempool(
		DefaultMempoolConfig(),
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)
	err := mempool.AddTransaction(tx, tx.Serialize())
	if err == nil {
		t.Fatal("expected tampered RingCT key image transaction to be rejected by mempool")
	}
	if !strings.Contains(err.Error(), "key image does not match signed RingCT payload") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mempool.Size(); got != 0 {
		t.Fatalf("mempool should remain empty, size=%d", got)
	}
}

func TestMempoolRejectsUnsupportedTxVersion(t *testing.T) {
	tx := mustBuildValidRingCTBindingTestTx(t)
	tx.Version = 2

	mempool := NewMempool(
		DefaultMempoolConfig(),
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)
	err := mempool.AddTransaction(tx, tx.Serialize())
	if err == nil {
		t.Fatal("expected unsupported tx version to be rejected by mempool")
	}
	if !strings.Contains(err.Error(), "unsupported tx version") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mempool.Size(); got != 0 {
		t.Fatalf("mempool should remain empty, size=%d", got)
	}
}

func TestMempoolRejectsTrailingBytes(t *testing.T) {
	mempool := NewMempool(
		DefaultMempoolConfig(),
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)

	// Minimal parseable tx bytes; cryptographic validity is irrelevant here because
	// AddTransaction should fail closed on non-canonical txData before validation.
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

	err := mempool.AddTransaction(&Transaction{}, withTrailing)
	if err == nil {
		t.Fatal("expected trailing-byte tx to be rejected by mempool")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mempool.Size(); got != 0 {
		t.Fatalf("mempool should remain empty, size=%d", got)
	}
}
