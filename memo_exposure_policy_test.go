package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blocknet/wallet"
)

func TestPublicSurfacesExposeCiphertextOnlyForMemos(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, dCleanup := mustStartTestDaemon(t, chain)
	defer dCleanup()

	// Inject a tx directly into the mempool so explorer/public API can find it
	// without requiring a fully-valid RingCT transaction.
	var memo [wallet.MemoSize]byte
	for i := range memo {
		memo[i] = byte(i + 1)
	}
	tx := &Transaction{
		Version: 1,
		Fee:     1,
		Inputs:  []TxInput{{}}, // non-coinbase
		Outputs: []TxOutput{{EncryptedMemo: memo}},
	}
	txID, err := tx.TxID()
	if err != nil {
		t.Fatalf("failed to compute txid: %v", err)
	}

	d.mempool.mu.Lock()
	d.mempool.txByID[txID] = &MempoolEntry{
		Tx:     tx,
		TxID:   txID,
		TxData: tx.Serialize(),
		Size:   tx.Size(),
	}
	d.mempool.mu.Unlock()

	// Explorer: ensure ciphertext is displayed and no plaintext memo fields exist.
	exp := NewExplorer(d)
	{
		req := httptest.NewRequest("GET", "/tx/"+fmt.Sprintf("%x", txID), nil)
		rr := httptest.NewRecorder()
		exp.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("explorer /tx: unexpected status: got %d", rr.Code)
		}
		body := rr.Body.String()

		encMemoHex := fmt.Sprintf("%x", memo)
		if !strings.Contains(body, encMemoHex) {
			t.Fatalf("explorer /tx response missing encrypted memo hex")
		}
		if strings.Contains(body, "memo_text") || strings.Contains(body, "memo_hex") || strings.Contains(body, "payment_id") {
			t.Fatalf("explorer /tx response unexpectedly references plaintext memo fields")
		}
	}

	// Public API: ensure it returns the tx object (with encrypted_memo) but does
	// not surface plaintext memo fields.
	api := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	mux := http.NewServeMux()
	api.registerPublicRoutes(mux)
	{
		req := httptest.NewRequest("GET", "/api/tx/"+fmt.Sprintf("%x", txID), nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("public GET /api/tx: unexpected status: got %d", rr.Code)
		}
		body := rr.Body.String()

		if !strings.Contains(body, `"encrypted_memo"`) {
			t.Fatalf("public GET /api/tx response missing encrypted_memo field")
		}
		if strings.Contains(body, `"memo_text"`) || strings.Contains(body, `"memo_hex"`) || strings.Contains(body, `"payment_id"`) {
			t.Fatalf("public GET /api/tx unexpectedly includes plaintext memo fields")
		}
	}
}

