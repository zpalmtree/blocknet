package main

import "testing"

func TestIsCanonicalRingMember_RejectsReorgedOutOutput(t *testing.T) {
	chain, storage, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	genesis := chain.GetBlockByHeight(0)
	if genesis == nil {
		t.Fatal("expected genesis block")
	}

	makeTxWithOutput := func() (*Transaction, [32]byte, [32]byte, error) {
		pub, err := GenerateRistrettoKeypair()
		if err != nil {
			return nil, [32]byte{}, [32]byte{}, err
		}
		commit, err := GenerateRistrettoKeypair()
		if err != nil {
			return nil, [32]byte{}, [32]byte{}, err
		}
		tx := &Transaction{
			Version: 1,
			Inputs:  nil, // coinbase-like shape; sufficient for storage-level canonicality checks
			Outputs: []TxOutput{
				{
					PublicKey:  pub.PublicKey,
					Commitment: commit.PublicKey,
				},
			},
			Fee: 0,
		}
		return tx, pub.PublicKey, commit.PublicKey, nil
	}

	txA, pubA, commA, err := makeTxWithOutput()
	if err != nil {
		t.Fatalf("failed to build txA: %v", err)
	}
	blockA := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec,
			Difficulty: MinDifficulty,
		},
		Transactions: []*Transaction{txA},
	}
	hashA := blockA.Hash()
	txAID, err := txA.TxID()
	if err != nil {
		t.Fatalf("failed to hash txA: %v", err)
	}

	err = storage.CommitBlock(&BlockCommit{
		Block:     blockA,
		Height:    1,
		Hash:      hashA,
		Work:      2,
		IsMainTip: true,
		NewOutputs: []*UTXO{
			{
				TxID:        txAID,
				OutputIndex: 0,
				Output:      txA.Outputs[0],
				BlockHeight: 1,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to commit blockA: %v", err)
	}

	if !chain.IsCanonicalRingMember(pubA, commA) {
		t.Fatal("expected output from current main-chain blockA to be canonical")
	}

	txB, pubB, commB, err := makeTxWithOutput()
	if err != nil {
		t.Fatalf("failed to build txB: %v", err)
	}
	blockB := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec + 1,
			Difficulty: MinDifficulty,
		},
		Transactions: []*Transaction{txB},
	}
	hashB := blockB.Hash()

	err = storage.CommitReorg(&ReorgCommit{
		Disconnect: []*Block{blockA},
		Connect:    []*Block{blockB},
		NewTip:     hashB,
		NewHeight:  1,
		NewWork:    2,
	})
	if err != nil {
		t.Fatalf("failed to reorg from blockA to blockB: %v", err)
	}

	if chain.IsCanonicalRingMember(pubA, commA) {
		t.Fatal("expected blockA output to be non-canonical after reorg")
	}
	if !chain.IsCanonicalRingMember(pubB, commB) {
		t.Fatal("expected blockB output to be canonical after reorg")
	}
}
