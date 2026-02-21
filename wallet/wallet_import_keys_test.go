package wallet

import (
	"path/filepath"
	"testing"
)

func TestWallet_NewWalletFromStealthKeys_PersistsAndLoads(t *testing.T) {
	cfg := testWalletConfigNoCryptoDeps(t)
	filename := filepath.Join(t.TempDir(), "imported.wallet")
	password := []byte("pw")

	var keys StealthKeys
	for i := 0; i < 32; i++ {
		keys.SpendPrivKey[i] = byte(i + 1)
		keys.SpendPubKey[i] = byte(i + 2)
		keys.ViewPrivKey[i] = byte(i + 3)
		keys.ViewPubKey[i] = byte(i + 4)
	}

	w, err := NewWalletFromStealthKeys(filename, password, keys, cfg)
	if err != nil {
		t.Fatalf("NewWalletFromStealthKeys: %v", err)
	}
	if w.IsViewOnly() {
		t.Fatalf("expected imported spend/view-key wallet to be full wallet")
	}
	if mnemonic, err := w.Mnemonic(); err != nil || mnemonic != "" {
		t.Fatalf("expected empty mnemonic, got %q err=%v", mnemonic, err)
	}

	loaded, err := LoadWallet(filename, password, cfg)
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	got := loaded.Keys()
	if got != keys {
		t.Fatalf("loaded keys mismatch")
	}
}
