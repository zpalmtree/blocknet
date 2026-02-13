package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"blocknet/wallet"
)

func TestHandleUnlock_BackoffAndRetryAfter(t *testing.T) {
	s := NewAPIServer(nil, &wallet.Wallet{}, nil, t.TempDir(), []byte("correct-password"))
	ip := "198.51.100.10"
	s.unlockAttempts.clients[ip] = &unlockAttemptState{
		failures:    1,
		nextAllowed: time.Now().Add(2 * time.Second),
		lastSeen:    time.Now(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = ip + ":12345"
		s.handleUnlock(w, r)
	})

	resp := mustMakeHTTPJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/api/wallet/unlock",
		[]byte(`{"password":"wrong-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected backoff precheck to return 429, got %d", resp.Code)
	}
	if ra := resp.Header().Get("Retry-After"); ra == "" {
		t.Fatal("expected Retry-After header on unlock backoff response")
	}
	if !strings.Contains(resp.Body.String(), "unlock backoff active") {
		t.Fatalf("unexpected 429 response body: %s", resp.Body.String())
	}
}

func TestHandleUnlock_SuccessResetsAttemptState(t *testing.T) {
	s := NewAPIServer(nil, &wallet.Wallet{}, nil, t.TempDir(), []byte("correct-password"))
	ip := "203.0.113.21"
	s.unlockAttempts.clients[ip] = &unlockAttemptState{
		failures: 3,
		lastSeen: time.Now(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = ip + ":54321"
		s.handleUnlock(w, r)
	})

	resp := mustMakeHTTPJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/api/wallet/unlock",
		[]byte(`{"password":"correct-password"}`),
		map[string]string{"Content-Type": "application/json"},
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected successful unlock to return 200, got %d", resp.Code)
	}
	if s.isLocked() {
		t.Fatal("wallet should be unlocked after correct password")
	}

	if wait, lockedUntil := s.unlockAttempts.precheck(ip); wait != 0 || !lockedUntil.IsZero() {
		t.Fatalf("unlock attempt state should be reset after success (wait=%s lockedUntil=%v)", wait, lockedUntil)
	}
}
