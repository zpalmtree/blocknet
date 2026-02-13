package main

import "testing"

func TestMempoolOnBlockDisconnected_ReaddsNonCoinbaseOnly(t *testing.T) {
	m := NewMempool(
		DefaultMempoolConfig(),
		func([32]byte) bool { return false },
		func([32]byte, [32]byte) bool { return true },
	)

	coinbase := &Transaction{
		Version: 1,
		Inputs:  nil,
		Outputs: []TxOutput{{PublicKey: [32]byte{0xA1}, Commitment: [32]byte{0xB1}}},
		Fee:     0,
	}
	normal := &Transaction{
		Version: 1,
		Inputs:  []TxInput{{KeyImage: [32]byte{0x11}}},
		Outputs: []TxOutput{{PublicKey: [32]byte{0xA2}, Commitment: [32]byte{0xB2}}},
		Fee:     1,
	}
	block := &Block{Transactions: []*Transaction{coinbase, normal}}

	normalID, err := normal.TxID()
	if err != nil {
		t.Fatalf("failed to compute normal txid: %v", err)
	}
	m.OnBlockDisconnected(block, map[[32]byte][]byte{
		normalID: normal.Serialize(),
	})

	if got := m.Size(); got != 1 {
		t.Fatalf("expected exactly one requeued tx, got size=%d", got)
	}
	if _, ok := m.GetTransaction(normalID); !ok {
		t.Fatal("expected non-coinbase transaction to be requeued")
	}
}

func TestMempoolOnBlockConnected_RemovesConfirmedAndConflicts(t *testing.T) {
	m := NewMempool(
		DefaultMempoolConfig(),
		func([32]byte) bool { return false },
		func([32]byte, [32]byte) bool { return true },
	)

	confirmedKI := [32]byte{0x44}
	conflictKI := [32]byte{0x55}
	confirmed := &Transaction{
		Version: 1,
		Inputs:  []TxInput{{KeyImage: confirmedKI}},
		Outputs: []TxOutput{{PublicKey: [32]byte{0x01}, Commitment: [32]byte{0x02}}},
		Fee:     1,
	}
	conflict := &Transaction{
		Version: 1,
		Inputs:  []TxInput{{KeyImage: conflictKI}}, // conflicts by key image with different block tx
		Outputs: []TxOutput{{PublicKey: [32]byte{0x03}, Commitment: [32]byte{0x04}}},
		Fee:     1,
	}
	blockConflict := &Transaction{
		Version: 1,
		Inputs:  []TxInput{{KeyImage: conflictKI}}, // same key image as mempool conflict tx
		Outputs: []TxOutput{{PublicKey: [32]byte{0x05}, Commitment: [32]byte{0x06}}},
		Fee:     1,
	}

	confirmedID, err := confirmed.TxID()
	if err != nil {
		t.Fatalf("failed to compute confirmed txid: %v", err)
	}
	conflictID, err := conflict.TxID()
	if err != nil {
		t.Fatalf("failed to compute conflict txid: %v", err)
	}

	// Seed mempool directly (same package; no mocks).
	confirmedData := confirmed.Serialize()
	conflictData := conflict.Serialize()
	m.txByID[confirmedID] = &MempoolEntry{Tx: confirmed, TxID: confirmedID, TxData: confirmedData, Size: len(confirmedData), Fee: 1, FeeRate: 1, index: -1}
	m.txByID[conflictID] = &MempoolEntry{Tx: conflict, TxID: conflictID, TxData: conflictData, Size: len(conflictData), Fee: 1, FeeRate: 1, index: -1}
	m.txByImage[confirmedKI] = confirmedID
	m.txByImage[conflictKI] = conflictID
	m.totalSize = len(confirmedData) + len(conflictData)

	block := &Block{Transactions: []*Transaction{confirmed, blockConflict}}
	m.OnBlockConnected(block)

	if _, ok := m.GetTransaction(confirmedID); ok {
		t.Fatal("expected confirmed tx to be removed on block connect")
	}
	if _, ok := m.GetTransaction(conflictID); ok {
		t.Fatal("expected conflicting tx (same key image) to be removed on block connect")
	}
}
