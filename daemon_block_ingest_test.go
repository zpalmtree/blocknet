package main

import (
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestDaemonProcessBlockDataRejectsOmittedEncryptedMemoAndDoesNotMutateTip(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, dCleanup := mustStartTestDaemon(t, chain)
	defer dCleanup()

	wantHash := chain.BestHash()
	wantHeight := chain.Height()

	// `encrypted_memo` intentionally omitted in the coinbase output.
	blockJSON := []byte(`{
	  "header": { "Version": 1, "Height": 1 },
	  "transactions": [
	    { "version": 1, "inputs": [], "outputs": [ {} ], "fee": 0 }
	  ]
	}`)

	err := d.processBlockData(blockJSON)
	if err == nil {
		t.Fatal("expected processBlockData to reject omitted encrypted_memo")
	}
	if !strings.Contains(err.Error(), "encrypted memo must not be all-zero") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTipUnchanged(t, chain, wantHash, wantHeight)
}

func TestDaemonHandleBlockRejectsOmittedEncryptedMemoAndDoesNotMutateTip(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, dCleanup := mustStartTestDaemon(t, chain)
	defer dCleanup()

	wantHash := chain.BestHash()
	wantHeight := chain.Height()

	blockJSON := []byte(`{
	  "header": { "Version": 1, "Height": 1 },
	  "transactions": [
	    { "version": 1, "inputs": [], "outputs": [ {} ], "fee": 0 }
	  ]
	}`)

	d.handleBlock(peer.ID("test-peer"), blockJSON)
	assertTipUnchanged(t, chain, wantHash, wantHeight)
}

