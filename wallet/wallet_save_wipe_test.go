package wallet

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func testWalletConfigNoCryptoDeps(t *testing.T) WalletConfig {
	t.Helper()
	return WalletConfig{
		// For these tests we only need deterministic, non-nil keys so the wallet
		// can be serialized. None of the stealth-crypto callbacks are exercised.
		GenerateKeypairFromSeed: func(seed [32]byte) (priv, pub [32]byte, err error) {
			// Use stdlib crypto to avoid depending on main package FFI crypto in wallet tests.
			k := ed25519.NewKeyFromSeed(seed[:])
			copy(priv[:], seed[:])
			copy(pub[:], k.Public().(ed25519.PublicKey))
			return priv, pub, nil
		},
	}
}

func TestWallet_MnemonicNotRetainedInMemory_AfterCreateAndLoad(t *testing.T) {
	cfg := testWalletConfigNoCryptoDeps(t)
	filename := filepath.Join(t.TempDir(), "wallet.json.enc")

	pw := []byte("correct horse battery staple")
	pwCopy := cloneBytes(pw)

	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	w, err := NewWalletFromMnemonic(filename, pw, mnemonic, cfg)
	if err != nil {
		t.Fatalf("NewWalletFromMnemonic: %v", err)
	}

	// Caller can wipe their password buffer; wallet cloned what it needs.
	wipeBytes(pw)
	if bytes.Equal(w.password, pw) {
		t.Fatalf("expected wallet password clone to be independent of caller slice")
	}
	if len(w.password) == 0 || bytes.Count(w.password, []byte{0}) == len(w.password) {
		t.Fatalf("expected wallet to still have a non-zero password buffer after caller wipe")
	}

	// Key property: mnemonic must not remain resident in the long-lived struct.
	if w.data.Mnemonic != "" {
		t.Fatalf("expected in-memory mnemonic to be cleared after wallet creation")
	}

	// Mnemonic() must read from disk and must not populate the struct field.
	got, err := w.Mnemonic()
	if err != nil {
		t.Fatalf("Mnemonic(): %v", err)
	}
	if got != mnemonic {
		t.Fatalf("Mnemonic(): mismatch")
	}
	if w.data.Mnemonic != "" {
		t.Fatalf("expected Mnemonic() to not cache mnemonic in struct")
	}

	// Save should preserve the on-disk mnemonic even when in-memory field is empty.
	if err := w.Save(); err != nil {
		t.Fatalf("Save(): %v", err)
	}
	got2, err := w.Mnemonic()
	if err != nil {
		t.Fatalf("Mnemonic() after Save: %v", err)
	}
	if got2 != mnemonic {
		t.Fatalf("Mnemonic() after Save: mismatch")
	}

	// Reload: the loaded wallet must also clear in-memory mnemonic while preserving on-disk access.
	pwLoad := cloneBytes(pwCopy)
	w2, err := LoadWallet(filename, pwLoad, cfg)
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	if w2.data.Mnemonic != "" {
		t.Fatalf("expected in-memory mnemonic to be cleared on LoadWallet")
	}

	// Wipe caller password; wallet clone must remain usable.
	wipeBytes(pwLoad)
	got3, err := w2.Mnemonic()
	if err != nil {
		t.Fatalf("Mnemonic() after LoadWallet: %v", err)
	}
	if got3 != mnemonic {
		t.Fatalf("Mnemonic() after LoadWallet: mismatch")
	}
	if w2.data.Mnemonic != "" {
		t.Fatalf("expected Mnemonic() to not cache mnemonic in struct after load")
	}
}

func TestWallet_Save_PreservesExistingDiskMnemonicWhenMemoryEmpty(t *testing.T) {
	cfg := testWalletConfigNoCryptoDeps(t)
	filename := filepath.Join(t.TempDir(), "wallet.json.enc")

	pw := []byte("pw")

	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	w, err := NewWalletFromMnemonic(filename, pw, mnemonic, cfg)
	if err != nil {
		t.Fatalf("NewWalletFromMnemonic: %v", err)
	}

	// Ensure in-memory mnemonic is empty (this is the production behavior we want).
	if w.data.Mnemonic != "" {
		t.Fatalf("expected mnemonic cleared after create")
	}

	// Save again; it should re-read mnemonic from disk and include it in the persisted blob.
	if err := w.Save(); err != nil {
		t.Fatalf("Save(): %v", err)
	}

	// Verify mnemonic is still present on disk (read path decrypts and extracts it).
	got, err := w.readMnemonicFromDisk()
	if err != nil {
		t.Fatalf("readMnemonicFromDisk(): %v", err)
	}
	if got != mnemonic {
		t.Fatalf("readMnemonicFromDisk(): mismatch")
	}
}

