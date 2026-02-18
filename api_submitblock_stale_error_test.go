package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleSubmitBlock_ReturnsHumanStaleMessage(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d := &Daemon{chain: chain}
	s := NewAPIServer(d, nil, nil, t.TempDir(), nil)

	// Submit a block at the "next height" but with a prev-hash that doesn't link
	// to the current tip. This should be treated as stale work and not leak
	// internal validator strings.
	var wrongPrev [32]byte
	wrongPrev[0] = 1
	block := Block{
		Header: BlockHeader{
			Version:  1,
			Height:   chain.Height() + 1,
			PrevHash: wrongPrev,
		},
	}
	body, err := json.Marshal(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mining/submitblock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleSubmitBlock(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%q)", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected JSON error body, got body=%q (err=%v)", rr.Body.String(), err)
	}
	if got := resp["error"]; got != "block rejected as stale" {
		t.Fatalf("unexpected error message: got %q", got)
	}

	// Ensure we don't leak internal validator strings.
	if _, ok := resp["details"]; ok {
		t.Fatalf("should not return structured internal error details, got body=%q", rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("invalid prev hash")) {
		t.Fatalf("should not leak internal validator text, got body=%q", rr.Body.String())
	}
}

