package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"blocknet/wallet"
)

func addTestDecoyOutputs(t *testing.T, storage *Storage, count int) {
	t.Helper()

	for i := 0; i < count; i++ {
		kp, err := GenerateRistrettoKeypair()
		if err != nil {
			t.Fatalf("failed to generate decoy keypair %d: %v", i, err)
		}
		commit, err := CreatePedersenCommitment(uint64(i + 1000))
		if err != nil {
			t.Fatalf("failed to create decoy commitment %d: %v", i, err)
		}
		var memo [wallet.MemoSize]byte
		memo[0] = 0x01
		var txid [32]byte
		txid[0] = byte(i + 1)
		if err := storage.SaveOutput(&UTXO{
			TxID:        txid,
			OutputIndex: 0,
			BlockHeight: 1,
			Output: TxOutput{
				PublicKey:     kp.PublicKey,
				Commitment:    commit.Commitment,
				EncryptedMemo: memo,
			},
		}); err != nil {
			t.Fatalf("failed to save decoy output %d: %v", i, err)
		}
	}
}

func addFundedWalletOutput(t *testing.T, w *wallet.Wallet, amount uint64, txidSeed byte) {
	t.Helper()

	inKP, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("failed to generate input keypair: %v", err)
	}
	inCommit, err := CreatePedersenCommitment(amount)
	if err != nil {
		t.Fatalf("failed to create input commitment: %v", err)
	}
	var txid [32]byte
	txid[0] = txidSeed
	w.AddOutput(&wallet.OwnedOutput{
		TxID:           txid,
		OutputIndex:    0,
		Amount:         amount,
		Blinding:       inCommit.Blinding,
		OneTimePrivKey: inKP.PrivateKey,
		OneTimePubKey:  inKP.PublicKey,
		Commitment:     inCommit.Commitment,
		BlockHeight:    0,
		IsCoinbase:     false,
		Spent:          false,
	})
}

func seedCanonicalSpendableOutput(t *testing.T, chain *Chain, storage *Storage, w *wallet.Wallet, amount uint64) {
	t.Helper()

	genesis := chain.GetBlockByHeight(0)
	if genesis == nil {
		t.Fatal("expected genesis block")
	}

	realKP, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("failed to generate real input keypair: %v", err)
	}
	realCommit, err := CreatePedersenCommitment(amount)
	if err != nil {
		t.Fatalf("failed to create real input commitment: %v", err)
	}

	var outputs []TxOutput
	var newOutputs []*UTXO

	var realMemo [wallet.MemoSize]byte
	realMemo[0] = 0x01
	outputs = append(outputs, TxOutput{
		PublicKey:     realKP.PublicKey,
		Commitment:    realCommit.Commitment,
		EncryptedMemo: realMemo,
	})

	for i := 0; i < RingSize*3; i++ {
		kp, err := GenerateRistrettoKeypair()
		if err != nil {
			t.Fatalf("failed to generate decoy keypair %d: %v", i, err)
		}
		commit, err := CreatePedersenCommitment(uint64(i + 1000))
		if err != nil {
			t.Fatalf("failed to create decoy commitment %d: %v", i, err)
		}
		var memo [wallet.MemoSize]byte
		memo[0] = 0x01
		outputs = append(outputs, TxOutput{
			PublicKey:     kp.PublicKey,
			Commitment:    commit.Commitment,
			EncryptedMemo: memo,
		})
	}

	tx := &Transaction{
		Version: 1,
		Outputs: outputs,
	}
	txid, err := tx.TxID()
	if err != nil {
		t.Fatalf("failed to hash funding tx: %v", err)
	}
	for i, out := range outputs {
		newOutputs = append(newOutputs, &UTXO{
			TxID:        txid,
			OutputIndex: uint32(i),
			Output:      out,
			BlockHeight: 1,
		})
	}

	block := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     1,
			PrevHash:   genesis.Hash(),
			Timestamp:  genesis.Header.Timestamp + BlockIntervalSec,
			Difficulty: MinDifficulty,
		},
		Transactions: []*Transaction{tx},
	}
	if err := storage.CommitBlock(&BlockCommit{
		Block:      block,
		Height:     1,
		Hash:       block.Hash(),
		Work:       2,
		IsMainTip:  true,
		NewOutputs: newOutputs,
	}); err != nil {
		t.Fatalf("failed to commit funding block: %v", err)
	}

	w.AddOutput(&wallet.OwnedOutput{
		TxID:           txid,
		OutputIndex:    0,
		Amount:         amount,
		Blinding:       realCommit.Blinding,
		OneTimePrivKey: realKP.PrivateKey,
		OneTimePubKey:  realKP.PublicKey,
		Commitment:     realCommit.Commitment,
		BlockHeight:    1,
		IsCoinbase:     false,
		Spent:          false,
	})
}

func TestHandleSendIdempotencyKeyReplayAndMismatch(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	chain.mu.Lock()
	chain.height = 100
	chain.mu.Unlock()

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	walletFile := filepath.Join(t.TempDir(), "wallet.dat")
	w, err := wallet.NewWallet(walletFile, []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}
	addFundedWalletOutput(t, w, 10_000_000, 0x01)

	recipient, err := wallet.NewWallet(filepath.Join(t.TempDir(), "recipient.dat"), []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create recipient wallet: %v", err)
	}

	api := NewAPIServer(daemon, w, nil, t.TempDir(), []byte("pw"))
	mux := http.NewServeMux()
	api.registerPublicRoutes(mux)
	api.registerPrivateRoutes(mux)

	token := "test-token"
	var handler http.Handler = mux
	handler = authMiddleware(token, handler)
	handler = maxBodySize(handler, maxRequestBodyBytes)

	doReq := func(body []byte, idemKey string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/wallet/send", bytes.NewReader(body))
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if idemKey != "" {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	body1 := []byte(`{"address":"` + recipient.Address() + `","amount":1,"memo_hex":"0"}`) // invalid hex -> 400
	body2 := []byte(`{"address":"` + recipient.Address() + `","amount":1,"memo_hex":"00"}`)

	// First request stores deterministic result for key-1.
	r1 := doReq(body1, "key-1")
	if r1.Code != http.StatusBadRequest {
		t.Fatalf("first request: expected 400, got %d: %s", r1.Code, r1.Body.String())
	}
	firstBody := r1.Body.String()
	if !strings.Contains(firstBody, "invalid memo_hex") {
		t.Fatalf("first request: unexpected body: %s", firstBody)
	}

	// Second identical request should replay exact first response.
	r2 := doReq(body1, "key-1")
	if r2.Code != r1.Code {
		t.Fatalf("replay request: status mismatch got %d want %d", r2.Code, r1.Code)
	}
	if r2.Body.String() != firstBody {
		t.Fatalf("replay request: body mismatch got %q want %q", r2.Body.String(), firstBody)
	}

	// Same key with a different payload must fail closed.
	r3 := doReq(body2, "key-1")
	if r3.Code != http.StatusConflict {
		t.Fatalf("mismatch request: expected 409, got %d: %s", r3.Code, r3.Body.String())
	}
	if !strings.Contains(r3.Body.String(), "idempotency key reuse with different request") {
		t.Fatalf("mismatch request: unexpected body: %s", r3.Body.String())
	}

	// New key should still be admitted (proves replay path did not consume limiter tokens).
	r4 := doReq(body1, "key-2")
	if r4.Code != http.StatusBadRequest {
		t.Fatalf("new-key request: expected 400, got %d: %s", r4.Code, r4.Body.String())
	}
}

func TestHandleSendIdempotencySuccessfulReplayPersistsAcrossRestart(t *testing.T) {
	chain, storage, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	chain.mu.Lock()
	chain.height = 100
	chain.mu.Unlock()

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	walletFile := filepath.Join(t.TempDir(), "wallet.dat")
	sender, err := wallet.NewWallet(walletFile, []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create sender wallet: %v", err)
	}
	seedCanonicalSpendableOutput(t, chain, storage, sender, 10_000_000)
	if err := sender.Save(); err != nil {
		t.Fatalf("failed to save sender wallet: %v", err)
	}

	recipient, err := wallet.NewWallet(filepath.Join(t.TempDir(), "recipient.dat"), []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create recipient wallet: %v", err)
	}

	dataDir := t.TempDir()
	token := "test-token"
	newHandler := func(w *wallet.Wallet) http.Handler {
		api := NewAPIServer(daemon, w, nil, dataDir, []byte("pw"))
		mux := http.NewServeMux()
		api.registerPublicRoutes(mux)
		api.registerPrivateRoutes(mux)

		var handler http.Handler = mux
		handler = authMiddleware(token, handler)
		handler = maxBodySize(handler, maxRequestBodyBytes)
		return handler
	}

	doReq := func(handler http.Handler, body []byte, idemKey string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/wallet/send", bytes.NewReader(body))
		req.RemoteAddr = "198.51.100.30:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if idemKey != "" {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	body := []byte(`{"address":"` + recipient.Address() + `","amount":1,"memo_hex":"00"}`)
	firstHandler := newHandler(sender)
	r1 := doReq(firstHandler, body, "key-success")
	if r1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d: %s", r1.Code, r1.Body.String())
	}
	firstBody := r1.Body.String()

	reloaded, err := wallet.LoadWallet(walletFile, []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to reload sender wallet: %v", err)
	}
	secondHandler := newHandler(reloaded)
	r2 := doReq(secondHandler, body, "key-success")
	if r2.Code != http.StatusOK {
		t.Fatalf("replay after restart: expected 200, got %d: %s", r2.Code, r2.Body.String())
	}
	if r2.Body.String() != firstBody {
		t.Fatalf("replay after restart: body mismatch got %q want %q", r2.Body.String(), firstBody)
	}
}

func TestHandleSendInsufficientFundsAfterFeeAdjustmentIsBadRequest(t *testing.T) {
	chain, storage, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	chain.mu.Lock()
	chain.height = 100
	chain.mu.Unlock()

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	walletFile := filepath.Join(t.TempDir(), "wallet.dat")
	sender, err := wallet.NewWallet(walletFile, []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create sender wallet: %v", err)
	}
	seedCanonicalSpendableOutput(t, chain, storage, sender, 10_000_000)

	recipient, err := wallet.NewWallet(filepath.Join(t.TempDir(), "recipient.dat"), []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create recipient wallet: %v", err)
	}

	api := NewAPIServer(daemon, sender, nil, t.TempDir(), []byte("pw"))
	mux := http.NewServeMux()
	api.registerPublicRoutes(mux)
	api.registerPrivateRoutes(mux)

	token := "test-token"
	var handler http.Handler = mux
	handler = authMiddleware(token, handler)
	handler = maxBodySize(handler, maxRequestBodyBytes)

	req := httptest.NewRequest(
		"POST",
		"/api/wallet/send",
		bytes.NewReader([]byte(`{"address":"`+recipient.Address()+`","amount":10000000}`)),
	)
	req.RemoteAddr = "198.51.100.40:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "insufficient funds") {
		t.Fatalf("expected insufficient-funds error, got %s", rr.Body.String())
	}
}
