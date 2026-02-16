package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blocknet/wallet"
)

func TestHandlePurge_ThrottleBlocksEvenCorrectPasswordDuringLockout(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := []byte("correct-password")

	walletPath := filepath.Join(t.TempDir(), "wallet.enc")
	writeTestWalletFileWithKDF(t, walletPath, password, []byte(mustWalletJSON(t, mnemonic)), testKDFParams{
		kdfVer:  1,
		time:    1,
		memKiB:  8 * 1024, // 8 MiB
		threads: 1,
	})

	w, err := wallet.LoadWallet(walletPath, password, wallet.WalletConfig{})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}

	dataDir := t.TempDir()
	sentinel := filepath.Join(dataDir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("do not delete"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	s := NewAPIServer(nil, w, nil, dataDir, password)
	ip := "198.51.100.99"

	doPurge := func(ctx context.Context, pw string, confirm bool) *httptest.ResponseRecorder {
		t.Helper()
		if ctx == nil {
			ctx = context.Background()
		}
		body := []byte(`{"password":"` + pw + `","confirm":` + boolJSON(confirm) + `}`)
		req := httptest.NewRequest(http.MethodPost, "/api/purge", bytes.NewReader(body))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		s.handlePurgeData(rr, req)
		return rr
	}

	// Seed to be one failure away from lockout, with no precheck backoff.
	s.unlockAttempts.clients[ip] = &unlockAttemptState{
		failures:     unlockFailuresToLockout - 1,
		nextAllowed:  time.Now().Add(-1 * time.Second),
		lockoutUntil: time.Time{},
		lastSeen:     time.Now(),
	}

	t.Run("wrong_password_triggers_lockout_429", func(t *testing.T) {
		// Cancel context so we don't wait out the deliberate failure delay.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resp := doPurge(ctx, "wrong-password", true)
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if ra := resp.Header().Get("Retry-After"); ra == "" {
			t.Fatal("expected Retry-After header on lockout response")
		}
		if !strings.Contains(resp.Body.String(), "too many attempts") {
			t.Fatalf("unexpected lockout response body: %q", resp.Body.String())
		}
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("expected data dir to remain intact during lockout (sentinel missing): %v", err)
		}
	})

	t.Run("correct_password_blocked_during_lockout_no_delete", func(t *testing.T) {
		resp := doPurge(context.Background(), "correct-password", true)
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if ra := resp.Header().Get("Retry-After"); ra == "" {
			t.Fatal("expected Retry-After header on lockout response")
		}
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("expected data dir to remain intact during lockout (sentinel missing): %v", err)
		}
	})

	t.Run("after_lockout_expires_confirm_required_without_deleting", func(t *testing.T) {
		// Force-expire lockout without waiting.
		s.unlockAttempts.mu.Lock()
		if st := s.unlockAttempts.clients[ip]; st != nil {
			st.lockoutUntil = time.Now().Add(-1 * time.Second)
			st.nextAllowed = time.Now().Add(-1 * time.Second)
			st.lastSeen = time.Now()
		}
		s.unlockAttempts.mu.Unlock()

		// Use correct password but confirm=false so handler stops before daemon.Stop/os.RemoveAll.
		resp := doPurge(context.Background(), "correct-password", false)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "confirmation required") {
			t.Fatalf("unexpected response body: %q", resp.Body.String())
		}
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("expected data dir to remain intact when confirm=false: %v", err)
		}
	})
}

func boolJSON(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

