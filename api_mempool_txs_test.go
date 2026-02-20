package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleMempoolTxsReturnsArrayAndFullTxObjects(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, dCleanup := mustStartTestDaemon(t, chain)
	defer dCleanup()

	api := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	mux := http.NewServeMux()
	api.registerPublicRoutes(mux)

	t.Run("empty mempool returns empty array", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/mempool/txs", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("unexpected status: got %d", rr.Code)
		}
		if strings.TrimSpace(rr.Body.String()) != "[]" {
			t.Fatalf("expected empty JSON array, got: %s", rr.Body.String())
		}
	})

	t.Run("non-empty mempool returns full tx objects", func(t *testing.T) {
		tx := &Transaction{
			Version: 1,
			Fee:     12345,
			Inputs:  []TxInput{{}}, // non-coinbase shape for test fixture
			Outputs: []TxOutput{{}},
		}
		txID, err := tx.TxID()
		if err != nil {
			t.Fatalf("failed to compute txid: %v", err)
		}

		d.mempool.mu.Lock()
		d.mempool.txByID[txID] = &MempoolEntry{
			Tx:      tx,
			TxID:    txID,
			TxData:  tx.Serialize(),
			Fee:     tx.Fee,
			FeeRate: 1,
			Size:    tx.Size(),
		}
		d.mempool.mu.Unlock()

		req := httptest.NewRequest("GET", "/api/mempool/txs", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("unexpected status: got %d", rr.Code)
		}

		var got []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 tx, got %d", len(got))
		}
		if _, ok := got[0]["inputs"]; !ok {
			t.Fatalf("expected tx object to include inputs: %#v", got[0])
		}
		if _, ok := got[0]["outputs"]; !ok {
			t.Fatalf("expected tx object to include outputs: %#v", got[0])
		}
		if _, ok := got[0]["tx_public_key"]; !ok {
			t.Fatalf("expected tx object to include tx_public_key: %#v", got[0])
		}
		if fee, ok := got[0]["fee"].(float64); !ok || uint64(fee) != 12345 {
			t.Fatalf("expected tx fee 12345, got %#v", got[0]["fee"])
		}
	})
}
