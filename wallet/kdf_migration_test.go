package wallet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/argon2"
)

func legacyEncryptForTest(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, walletEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Original hard-coded params: t=3, m=64MiB, p=4, keyLen=32.
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, walletEncKeyLen)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, walletEncSaltLen+len(nonce)+len(ciphertext))
	copy(out[:walletEncSaltLen], salt)
	copy(out[walletEncSaltLen:walletEncSaltLen+len(nonce)], nonce)
	copy(out[walletEncSaltLen+len(nonce):], ciphertext)
	return out, nil
}

func TestDecryptAcceptsLegacyAndCurrentFormats(t *testing.T) {
	password := []byte("correct horse battery staple")
	plaintext := []byte(`{"version":1,"view_only":false}`)

	// 1) Current format from encrypt()
	cur, err := encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("encrypt(current): %v", err)
	}
	if len(cur) < walletEncHeaderLenV1 {
		t.Fatalf("encrypt(current): too short: %d", len(cur))
	}
	if string(cur[:8]) != walletEncMagicV1 {
		t.Fatalf("encrypt(current): missing magic prefix")
	}
	decCur, err := decrypt(cur, password)
	if err != nil {
		t.Fatalf("decrypt(current): %v", err)
	}
	if !bytes.Equal(decCur, plaintext) {
		t.Fatalf("decrypt(current): plaintext mismatch")
	}

	// 2) Legacy format (salt||nonce||ct) produced by helper
	legacy, err := legacyEncryptForTest(plaintext, password)
	if err != nil {
		t.Fatalf("legacyEncryptForTest: %v", err)
	}
	decLegacy, err := decrypt(legacy, password)
	if err != nil {
		t.Fatalf("decrypt(legacy): %v", err)
	}
	if !bytes.Equal(decLegacy, plaintext) {
		t.Fatalf("decrypt(legacy): plaintext mismatch")
	}
}

