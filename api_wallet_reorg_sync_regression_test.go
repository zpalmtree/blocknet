package main

import (
	"net/http"
	"testing"

	"blocknet/wallet"
)

func TestHandleLoadWallet_ReorgAtSameHeight_RewindsStaleWalletState(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	// Simulate a chain that is currently at height 2.
	chain.mu.Lock()
	chain.height = 2
	chain.mu.Unlock()

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	walletPath := t.TempDir() + "/wallet.dat"
	pass := []byte("correct-password")

	w, err := wallet.NewWallet(walletPath, pass, defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	// Simulate stale state from an orphaned branch at the same height:
	// wallet thinks it has an output and is synced to height 2.
	w.AddOutput(&wallet.OwnedOutput{
		TxID:        [32]byte{0xAB},
		OutputIndex: 0,
		Amount:      12345,
		BlockHeight: 2,
	})
	w.SetSyncedHeight(2)
	if err := w.Save(); err != nil {
		t.Fatalf("failed to save stale wallet fixture: %v", err)
	}

	s := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	s.cli = &CLI{walletFile: walletPath}

	resp := mustMakeHTTPJSONRequest(
		t,
		http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "203.0.113.40:1234"
			s.handleLoadWallet(rw, r)
		}),
		http.MethodPost,
		"/api/wallet/load",
		[]byte(`{"password":"correct-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", resp.Code, resp.Body.String())
	}

	s.mu.RLock()
	loaded := s.wallet
	s.mu.RUnlock()
	if loaded == nil {
		t.Fatal("expected loaded wallet")
	}

	_, unspent := loaded.OutputCount()
	if unspent != 0 {
		t.Fatalf("expected stale outputs to be rewound on same-height reorg load, got unspent=%d", unspent)
	}
}

func TestHandleLoadWallet_CatchupOnlyMarksScannedHeight(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	// Build a sparse/inconsistent view for regression:
	// Height reports 2, but block at height 2 is missing.
	genesis := chain.GetBlockByHeight(0)
	if genesis == nil {
		t.Fatal("expected genesis block")
	}
	block1 := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec,
			Difficulty: MinDifficulty,
		},
	}
	hash1 := block1.Hash()

	chain.mu.Lock()
	chain.blocks[hash1] = block1
	chain.byHeight[1] = hash1
	chain.height = 2 // deliberately ahead of available blocks
	chain.mu.Unlock()

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	walletPath := t.TempDir() + "/wallet.dat"
	if _, err := wallet.NewWallet(walletPath, []byte("correct-password"), defaultWalletConfig()); err != nil {
		t.Fatalf("failed to create wallet fixture: %v", err)
	}

	s := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	s.cli = &CLI{walletFile: walletPath}

	resp := mustMakeHTTPJSONRequest(
		t,
		http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "203.0.113.41:1234"
			s.handleLoadWallet(rw, r)
		}),
		http.MethodPost,
		"/api/wallet/load",
		[]byte(`{"password":"correct-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", resp.Code, resp.Body.String())
	}

	s.mu.RLock()
	loaded := s.wallet
	s.mu.RUnlock()
	if loaded == nil {
		t.Fatal("expected loaded wallet")
	}

	if got := loaded.SyncedHeight(); got != 1 {
		t.Fatalf("expected synced height to reflect last scanned block (1), got %d", got)
	}
}
