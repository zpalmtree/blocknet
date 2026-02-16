package main

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWalletLoadImport_SerializedByWalletLoadingGuard(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	d, stop := mustStartTestDaemon(t, chain)
	defer stop()

	walletPath := t.TempDir() + "/wallet.dat"
	s := NewAPIServer(d, nil, nil, t.TempDir(), nil)
	s.cli = &CLI{walletFile: walletPath}

	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	importRespCh := make(chan int, 1)
	var importBody string
	loadRespCh := make(chan int, 1)
	var loadBody string

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp := mustMakeHTTPJSONRequest(
			t,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = "203.0.113.10:1111"
				s.handleImportWallet(w, r)
			}),
			http.MethodPost,
			"/api/wallet/import",
			[]byte(`{"mnemonic":"`+mnemonic+`","password":"correct-password"}`),
			map[string]string{"Content-Type": "application/json"},
		)
		importBody = resp.Body.String()
		importRespCh <- resp.Code
	}()

	// Wait until import flips walletLoading, then attempt load.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		loading := s.walletLoading
		s.mu.RUnlock()
		if loading {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	respLoad := mustMakeHTTPJSONRequest(
		t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "203.0.113.10:2222"
			s.handleLoadWallet(w, r)
		}),
		http.MethodPost,
		"/api/wallet/load",
		[]byte(`{"password":"correct-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)
	loadBody = respLoad.Body.String()
	loadRespCh <- respLoad.Code

	wg.Wait()

	importCode := <-importRespCh
	loadCode := <-loadRespCh

	// Exactly one should succeed; the other should conflict due to walletLoading/wallet != nil.
	if (importCode == http.StatusOK) == (loadCode == http.StatusOK) {
		t.Fatalf("expected exactly one success: import=%d load=%d (importBody=%q loadBody=%q)", importCode, loadCode, importBody, loadBody)
	}
	if importCode != http.StatusOK && importCode != http.StatusConflict {
		t.Fatalf("unexpected import status: %d (body=%q)", importCode, importBody)
	}
	if loadCode != http.StatusOK && loadCode != http.StatusConflict {
		t.Fatalf("unexpected load status: %d (body=%q)", loadCode, loadBody)
	}
	if loadCode == http.StatusConflict && !strings.Contains(loadBody, "wallet already loaded") {
		t.Fatalf("unexpected load conflict body: %q", loadBody)
	}

	// Server should end in a consistent loaded state (walletLoading cleared, wallet/scanner published).
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.walletLoading {
		t.Fatal("expected walletLoading to be false at end")
	}
	if s.wallet == nil || s.scanner == nil {
		t.Fatalf("expected wallet and scanner to be published (wallet=%v scanner=%v)", s.wallet, s.scanner)
	}
	if !s.passwordHashSet {
		t.Fatal("expected passwordHashSet to be true")
	}
}

