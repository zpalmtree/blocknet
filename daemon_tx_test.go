package main

import (
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestDaemonTxIngestRejectsCoinbaseTransaction(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	keys, err := GenerateStealthKeys()
	if err != nil {
		t.Fatalf("failed to generate stealth keys: %v", err)
	}
	coinbase, err := CreateCoinbase(keys.SpendPubKey, keys.ViewPubKey, GetBlockReward(1), 1)
	if err != nil {
		t.Fatalf("failed to create coinbase tx: %v", err)
	}

	txData := coinbase.Tx.Serialize()
	if err := daemon.processTxData(txData); err != nil {
		t.Fatalf("processTxData returned unexpected error: %v", err)
	}

	txID, err := coinbase.Tx.TxID()
	if err != nil {
		t.Fatalf("failed to compute coinbase txid: %v", err)
	}
	if _, exists := daemon.Mempool().GetTransaction(txID); exists {
		t.Fatalf("coinbase transaction was admitted through daemon ingest: %x", txID[:8])
	}
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after daemon ingest coinbase attempt, size=%d", got)
	}
}

func TestDaemonTxIngestRejectsTamperedRingCTExternalKeyImage(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	// Isolate the RingCT binding behavior in daemon ingest without unrelated
	// canonical ring-member/storage coupling.
	daemon.mempool = NewMempool(
		DefaultMempoolConfig(),
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)

	tx := mustBuildValidRingCTBindingTestTx(t)
	tx.Inputs[0].KeyImage[0] ^= 0x01

	txData := tx.Serialize()
	if err := daemon.processTxData(txData); err != nil {
		t.Fatalf("processTxData returned unexpected error: %v", err)
	}

	txID, err := tx.TxID()
	if err != nil {
		t.Fatalf("failed to compute tampered txid: %v", err)
	}
	if _, exists := daemon.Mempool().GetTransaction(txID); exists {
		t.Fatalf("tampered RingCT transaction was admitted through daemon ingest: %x", txID[:8])
	}
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after daemon ingest tampered tx attempt, size=%d", got)
	}
}

func TestDaemonProcessTxDataRejectsTrailingBytes(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	// Minimal parseable tx bytes; cryptographic validity is irrelevant for this test.
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
	withTrailing := append(append([]byte(nil), canonical...), 0xDE, 0xAD)

	err := daemon.processTxData(withTrailing)
	if err == nil {
		t.Fatal("expected trailing-byte tx to be rejected by processTxData")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after trailing-byte ingest, size=%d", got)
	}
}

func TestDaemonHandleTxRejectsTrailingBytes(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

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
	withTrailing := append(append([]byte(nil), canonical...), 0x00)

	daemon.handleTx(peer.ID("peer"), withTrailing)
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after trailing-byte gossip ingest, size=%d", got)
	}
}
