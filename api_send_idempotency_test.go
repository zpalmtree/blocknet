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
	w.AddOutput(&wallet.OwnedOutput{
		TxID:        [32]byte{0x01},
		OutputIndex: 0,
		Amount:      10_000_000,
		BlockHeight: 0,
		IsCoinbase:  false,
		Spent:       false,
	})

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

	body1 := []byte(`{"address":"` + w.Address() + `","amount":1,"memo_hex":"0"}`) // invalid hex -> 400
	body2 := []byte(`{"address":"` + w.Address() + `","amount":1,"memo_hex":"00"}`)

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

