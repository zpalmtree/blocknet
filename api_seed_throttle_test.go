package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"os"
	"net/http"
	"strings"
	"testing"
	"time"

	"blocknet/wallet"
	"golang.org/x/crypto/argon2"
)

func TestHandleSeed_ThrottleLockoutAndRetryAfter(t *testing.T) {
	// Build a real wallet file so the success path is production-faithful, but
	// use a small KDF in the test-created file so the test runs quickly.
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := []byte("correct-password")

	walletPath := t.TempDir() + "/wallet.enc"
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

	s := NewAPIServer(nil, w, nil, t.TempDir(), password)
	ip := "203.0.113.77"

	// Seed attempt state to be one failure away from lockout, but with no backoff wait.
	s.unlockAttempts.clients[ip] = &unlockAttemptState{
		failures:     unlockFailuresToLockout - 1,
		nextAllowed:  time.Now().Add(-1 * time.Second),
		lockoutUntil: time.Time{},
		lastSeen:     time.Now(),
	}

	doSeed := func(ctx context.Context, pw string) *httptest.ResponseRecorder {
		t.Helper()
		if ctx == nil {
			ctx = context.Background()
		}
		req := httptest.NewRequest(http.MethodPost, "/api/wallet/seed", bytes.NewReader([]byte(`{"password":"`+pw+`"}`)))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":54321"
		rr := httptest.NewRecorder()
		s.handleSeed(rr, req)
		return rr
	}

	t.Run("wrong_password_triggers_lockout_429", func(t *testing.T) {
		// Cancel context so the handler doesn't sleep for the failure delay.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resp := doSeed(ctx, "wrong-password")
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected lockout 429, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if ra := resp.Header().Get("Retry-After"); ra == "" {
			t.Fatal("expected Retry-After header on lockout response")
		}
		if !strings.Contains(resp.Body.String(), "too many attempts") {
			t.Fatalf("unexpected 429 response body: %s", resp.Body.String())
		}
	})

	t.Run("correct_password_blocked_during_lockout", func(t *testing.T) {
		resp := doSeed(context.Background(), "correct-password")
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected lockout 429, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if ra := resp.Header().Get("Retry-After"); ra == "" {
			t.Fatal("expected Retry-After header on lockout response")
		}
	})

	t.Run("success_after_lockout_expires", func(t *testing.T) {
		// Force-expire lockout without waiting 30s.
		s.unlockAttempts.mu.Lock()
		if st := s.unlockAttempts.clients[ip]; st != nil {
			st.lockoutUntil = time.Now().Add(-1 * time.Second)
			st.nextAllowed = time.Now().Add(-1 * time.Second)
			st.lastSeen = time.Now()
		}
		s.unlockAttempts.mu.Unlock()

		resp := doSeed(context.Background(), "correct-password")
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body=%q)", resp.Code, resp.Body.String())
		}
		if cc := resp.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control=no-store, got %q", cc)
		}

		var body struct {
			Mnemonic string   `json:"mnemonic"`
			Words    []string `json:"words"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to parse response JSON: %v (body=%q)", err, resp.Body.String())
		}
		if body.Mnemonic != mnemonic {
			t.Fatalf("unexpected mnemonic: got %q", body.Mnemonic)
		}
		if len(body.Words) != 12 {
			t.Fatalf("expected 12 mnemonic words, got %d", len(body.Words))
		}

		// Success should reset state.
		if wait, lockedUntil := s.unlockAttempts.precheck(ip); wait != 0 || !lockedUntil.IsZero() {
			t.Fatalf("expected attempt state reset after success (wait=%s lockedUntil=%v)", wait, lockedUntil)
		}
	})
}

// ---- Test-only wallet file writer ----

type testKDFParams struct {
	kdfVer  uint8
	time    uint32
	memKiB  uint32
	threads uint8
}

func writeTestWalletFileWithKDF(t *testing.T, filename string, password []byte, plaintext []byte, p testKDFParams) {
	t.Helper()

	const (
		magic            = "BLKNTWLT"
		formatVersionV1  = uint8(1)
		saltLen          = 16
		keyLen           = 32
		headerLenV1      = 8 + 1 + 1 + 4 + 4 + 1 + 3
		reservedLen      = 3
	)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand salt: %v", err)
	}
	key := argon2.IDKey(password, salt, p.time, p.memKiB, p.threads, keyLen)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, headerLenV1+saltLen+len(nonce)+len(ct))
	off := 0
	copy(out[off:off+8], []byte(magic))
	off += 8
	out[off] = formatVersionV1
	off++
	out[off] = p.kdfVer
	off++
	binary.BigEndian.PutUint32(out[off:off+4], p.time)
	off += 4
	binary.BigEndian.PutUint32(out[off:off+4], p.memKiB)
	off += 4
	out[off] = p.threads
	off++
	off += reservedLen
	copy(out[off:off+saltLen], salt)
	off += saltLen
	copy(out[off:off+len(nonce)], nonce)
	off += len(nonce)
	copy(out[off:], ct)

	if err := os.WriteFile(filename, out, 0600); err != nil {
		t.Fatalf("write wallet file: %v", err)
	}
}

func mustWalletJSON(t *testing.T, mnemonic string) string {
	t.Helper()
	// Minimal wallet JSON that wallet.LoadWallet can parse.
	data := map[string]any{
		"version":    1,
		"view_only":  false,
		"mnemonic":   mnemonic,
		"keys": map[string]any{
			"spend_priv": make([]int, 32),
			"spend_pub":  make([]int, 32),
			"view_priv":  make([]int, 32),
			"view_pub":   make([]int, 32),
		},
		"outputs":       []any{},
		"synced_height": 0,
		"created_at":    0,
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal wallet json: %v", err)
	}
	return string(b)
}

