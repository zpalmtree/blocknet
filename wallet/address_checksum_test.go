package wallet

import (
	"strings"
	"testing"

	"blocknet/protocol/params"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

func TestAddressChecksum_TypoAndCrossNetworkRejected_LegacyAccepted(t *testing.T) {
	var spendPub, viewPub [32]byte
	for i := 0; i < 32; i++ {
		spendPub[i] = byte(0x10 + i)
		viewPub[i] = byte(0x80 + i)
	}

	keys := &StealthKeys{
		SpendPubKey: spendPub,
		ViewPubKey:  viewPub,
	}

	addr := keys.Address()
	if addr == "" {
		t.Fatal("expected non-empty address")
	}

	// Valid current-format address parses.
	gotSpend, gotView, err := ParseAddress(addr)
	if err != nil {
		t.Fatalf("ParseAddress(valid): %v", err)
	}
	if gotSpend != spendPub || gotView != viewPub {
		t.Fatalf("ParseAddress(valid): pubkey mismatch")
	}

	// Typo: flip one character; must fail (checksum or length).
	mut := mutateBase58Char(addr)
	if mut == addr {
		t.Fatal("expected mutated address to differ")
	}
	_, _, err = ParseAddress(mut)
	if err == nil {
		t.Fatalf("expected ParseAddress(typo) to fail")
	}

	// Cross-network: same payload but checksum computed under a different network ID.
	decoded := base58.Decode(addr)
	if len(decoded) != 68 {
		t.Fatalf("expected current-format decoded length 68, got %d", len(decoded))
	}
	payload := decoded[:64]

	otherNetChecksum := checksumForNetwork(payload, "blocknet_testnet")
	otherNetCombined := make([]byte, 0, 68)
	otherNetCombined = append(otherNetCombined, payload...)
	otherNetCombined = append(otherNetCombined, otherNetChecksum[:4]...)
	otherNetAddr := base58.Encode(otherNetCombined)

	_, _, err = ParseAddress(otherNetAddr)
	if err == nil || !strings.Contains(err.Error(), "invalid address checksum") {
		t.Fatalf("expected invalid address checksum, got %v", err)
	}

	// Legacy: base58(payload64) parses for backward compatibility.
	legacyAddr := base58.Encode(payload)
	ls, lv, err := ParseAddress(legacyAddr)
	if err != nil {
		t.Fatalf("ParseAddress(legacy): %v", err)
	}
	if ls != spendPub || lv != viewPub {
		t.Fatalf("ParseAddress(legacy): pubkey mismatch")
	}

	// Sanity: current checksum should be network-bound to params.NetworkID.
	curSum := checksumForNetwork(payload, params.NetworkID)
	if curSum[0] != decoded[64] || curSum[1] != decoded[65] || curSum[2] != decoded[66] || curSum[3] != decoded[67] {
		t.Fatal("expected current checksum to match params.NetworkID")
	}
}

func checksumForNetwork(payload []byte, networkID string) [32]byte {
	const tag = "blocknet_stealth_address_checksum"
	b := make([]byte, 0, len(tag)+len(networkID)+len(payload))
	b = append(b, tag...)
	b = append(b, networkID...)
	b = append(b, payload...)
	return sha3.Sum256(b)
}

func mutateBase58Char(s string) string {
	// Replace the last rune with a different base58 char.
	if s == "" {
		return s
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	last := s[len(s)-1]
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] != last {
			out := []byte(s)
			out[len(out)-1] = alphabet[i]
			return string(out)
		}
	}
	// Should never happen; if it does, force an invalid character.
	return s[:len(s)-1] + "0"
}
