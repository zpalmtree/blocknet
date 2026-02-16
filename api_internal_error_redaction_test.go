package main

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"
)

func TestWriteInternal_RedactsClientResponseButLogsDetail(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	// Set walletFile to a directory path so wallet.LoadOrCreateWallet fails with an internal error.
	badWalletPath := t.TempDir()
	s := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	s.cli = &CLI{walletFile: badWalletPath}

	var logs bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)

	resp := mustMakeHTTPJSONRequest(
		t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "198.51.100.20:1234"
			s.handleLoadWallet(w, r)
		}),
		http.MethodPost,
		"/api/wallet/load",
		[]byte(`{"password":"correct-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body=%q)", resp.Code, resp.Body.String())
	}

	// Client body should contain only the generic client message.
	body := resp.Body.String()
	if !strings.Contains(body, `"error":"internal error"`) {
		t.Fatalf("expected generic client error, got %q", body)
	}
	if strings.Contains(body, badWalletPath) || strings.Contains(body, "directory") || strings.Contains(body, "is a directory") {
		t.Fatalf("client response leaked internal details: %q", body)
	}

	// Logs should contain the detailed underlying error (path/state).
	logText := logs.String()
	if !strings.Contains(logText, "API internal error: POST /api/wallet/load:") {
		t.Fatalf("expected API internal error log prefix, got %q", logText)
	}
	// Platform-dependent phrasing is ok; we just require it's not empty and includes the path.
	if !strings.Contains(logText, badWalletPath) {
		t.Fatalf("expected logs to include underlying error details (path), got %q", logText)
	}
}

