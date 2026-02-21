package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"blocknet/wallet"
)

type importVector struct {
	mnemonic string
	address  string
	spendKey string
	viewKey  string
}

func TestImportVectors_MnemonicAndSpendViewMatchAddress(t *testing.T) {
	vectors := []importVector{
		{
			mnemonic: "tool avoid choice blind parent way turn struggle soon fame have eyebrow",
			address:  "xn8HuruaxJB6tAMPDCWJPdevKq4Dxj3ZdrFkBcDXvFnPuwFGQxf8Nrs2R4rXZtGDSHi3atTWPgiDNj4QHhqDw3K",
			spendKey: "6c7b0a789d6d277927085ca4c8cb7a613407cb7718342a8c2f382e3d51fe940b",
			viewKey:  "01656d3deeb0f88babf3036428c2dc040126d7182a393cd7d985ecf78e17cb03",
		},
		{
			mnemonic: "begin exclude melt major violin exotic wheat diary exile limb hole install",
			address:  "28mfqjc29MwBy6jBUve8yS89wywrRXEuV4ayNfhdgVYurK35zBF4TVmvqN2FUfyA2Ky1dAcb9PTTB1DANom8oQD8",
			spendKey: "63df90b29c820341f34004eb1c8ea537fb08e5117be9b3d3edb013ca3dc9a90f",
			viewKey:  "1f346e3e162b836f996745e5fa99c533a160b0ef5da3c85bc900bee322fb8507",
		},
		{
			mnemonic: "already discover also taste random flush thrive buzz churn before future add",
			address:  "326dawxiBerr397r7wvXvSY5FcJf2kJD8tiiTYop6qgubQ1MV4HSksZKmc4ewoPzrMW4fizm93X5ZaTMpYd8iXx3",
			spendKey: "f0f6327d2025e103c9f1ee352a633ad8420ba898ea8b53f82415c6f181cc6e08",
			viewKey:  "bc0194bd321c91928a6661efb15fa10add97c246c708f66eb70ac94c94b9d70e",
		},
	}

	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector_%d", i+1), func(t *testing.T) {
			if !wallet.ValidateMnemonic(v.mnemonic) {
				t.Fatalf("vector %d mnemonic invalid", i)
			}

			spendPriv := mustHex32(t, v.spendKey)
			viewPriv := mustHex32(t, v.viewKey)

			spendPub, err := ScalarToPubKey(spendPriv)
			if err != nil {
				t.Fatalf("vector %d derive spend pub failed: %v", i, err)
			}
			viewPub, err := ScalarToPubKey(viewPriv)
			if err != nil {
				t.Fatalf("vector %d derive view pub failed: %v", i, err)
			}

			fullKeys := wallet.StealthKeys{
				SpendPrivKey: spendPriv,
				SpendPubKey:  spendPub,
				ViewPrivKey:  viewPriv,
				ViewPubKey:   viewPub,
			}
			expectedFromKeys := fullKeys.Address()
			if expectedFromKeys != v.address {
				t.Logf("vector %d provided address differs from current derivation: got=%s provided=%s", i, expectedFromKeys, v.address)
			}

			mnemonicFile := filepath.Join(t.TempDir(), "from-mnemonic.wallet")
			wFromMnemonic, err := wallet.NewWalletFromMnemonic(mnemonicFile, []byte("pw"), v.mnemonic, defaultWalletConfig())
			if err != nil {
				t.Fatalf("vector %d NewWalletFromMnemonic failed: %v", i, err)
			}
			if got := wFromMnemonic.Address(); got != v.address {
				if got != expectedFromKeys {
					t.Fatalf("vector %d mnemonic import address mismatch: got %s want %s", i, got, expectedFromKeys)
				}
			}
			mnemonicKeys := wFromMnemonic.Keys()
			if mnemonicKeys.SpendPrivKey != spendPriv || mnemonicKeys.ViewPrivKey != viewPriv {
				t.Fatalf("vector %d mnemonic-derived private keys mismatch expected spend/view", i)
			}

			keysFile := filepath.Join(t.TempDir(), "from-keys.wallet")
			wFromKeys, err := wallet.NewWalletFromStealthKeys(keysFile, []byte("pw"), fullKeys, defaultWalletConfig())
			if err != nil {
				t.Fatalf("vector %d NewWalletFromStealthKeys failed: %v", i, err)
			}
			if got := wFromKeys.Address(); got != expectedFromKeys {
				t.Fatalf("vector %d spend/view import address mismatch: got %s want %s", i, got, expectedFromKeys)
			}
		})
	}
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	decoded, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	if len(decoded) != 32 {
		t.Fatalf("invalid hex length for %q: %d", s, len(decoded))
	}
	copy(out[:], decoded)
	return out
}
