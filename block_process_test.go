package main

import (
	"strings"
	"testing"
)

func TestProcessBlock_EnforcesValidationInternally(t *testing.T) {
	chain, storage, cleanup := mustCreateTestChain(t)
	defer cleanup()

	mustAddGenesisBlock(t, chain)

	genesis := chain.GetBlockByHeight(0)
	if genesis == nil {
		t.Fatal("expected genesis block at height 0")
	}

	prevTipHash := chain.BestHash()
	prevTipHeight := chain.Height()

	invalid := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     genesis.Header.Height + 1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec,
			Difficulty: MinDifficulty + 1, // should be MinDifficulty in early epoch
		},
		Transactions: nil,
	}

	accepted, isMainChain, err := chain.ProcessBlock(invalid)
	if err == nil {
		t.Fatal("expected ProcessBlock to reject invalid block")
	}
	if !strings.Contains(err.Error(), "invalid difficulty") {
		t.Fatalf("expected invalid difficulty error, got: %v", err)
	}
	if accepted {
		t.Fatal("invalid block should not be accepted")
	}
	if isMainChain {
		t.Fatal("invalid block must not be marked as main chain")
	}

	assertTipUnchanged(t, chain, prevTipHash, prevTipHeight)

	invalidHash := invalid.Hash()
	if storage.HasBlock(invalidHash) {
		t.Fatalf("invalid block was persisted in storage: %x", invalidHash[:8])
	}
	if got := chain.GetBlock(invalidHash); got != nil {
		t.Fatalf("invalid block was cached in chain memory: %x", invalidHash[:8])
	}
}

func TestProcessLocalSubmitBlock_StillEnforcesNonPoWRules(t *testing.T) {
	chain, storage, cleanup := mustCreateTestChain(t)
	defer cleanup()

	mustAddGenesisBlock(t, chain)

	genesis := chain.GetBlockByHeight(0)
	if genesis == nil {
		t.Fatal("expected genesis block at height 0")
	}

	prevTipHash := chain.BestHash()
	prevTipHeight := chain.Height()

	invalid := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     genesis.Header.Height + 1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec,
			Difficulty: MinDifficulty + 1, // should be MinDifficulty in early epoch
		},
		Transactions: nil,
	}

	accepted, isMainChain, err := chain.ProcessLocalSubmitBlock(invalid)
	if err == nil {
		t.Fatal("expected ProcessLocalSubmitBlock to reject invalid block")
	}
	if !strings.Contains(err.Error(), "invalid difficulty") {
		t.Fatalf("expected invalid difficulty error, got: %v", err)
	}
	if accepted {
		t.Fatal("invalid block should not be accepted")
	}
	if isMainChain {
		t.Fatal("invalid block must not be marked as main chain")
	}

	assertTipUnchanged(t, chain, prevTipHash, prevTipHeight)

	invalidHash := invalid.Hash()
	if storage.HasBlock(invalidHash) {
		t.Fatalf("invalid block was persisted in storage: %x", invalidHash[:8])
	}
	if got := chain.GetBlock(invalidHash); got != nil {
		t.Fatalf("invalid block was cached in chain memory: %x", invalidHash[:8])
	}
}

func TestShouldSkipPoWForProcessLocked_LocalSubmitTipExtension(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	block := &Block{
		Header: BlockHeader{
			Height:   chain.Height() + 1,
			PrevHash: chain.BestHash(),
		},
	}

	chain.mu.RLock()
	defer chain.mu.RUnlock()

	if !chain.shouldSkipPoWForProcessLocked(block, true) {
		t.Fatal("expected local tip-extension submit to skip PoW revalidation")
	}
	if chain.shouldSkipPoWForProcessLocked(block, false) {
		t.Fatal("expected regular process path to keep PoW validation enabled")
	}
}

func TestShouldSkipPoWForProcessLocked_DoesNotSkipForkLocalSubmit(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	block := &Block{
		Header: BlockHeader{
			Height:   chain.Height() + 1,
			PrevHash: [32]byte{0xAA}, // does not extend tip
		},
	}

	chain.mu.RLock()
	defer chain.mu.RUnlock()

	if chain.shouldSkipPoWForProcessLocked(block, true) {
		t.Fatal("expected local submit PoW skip to apply only to direct tip extensions")
	}
}
