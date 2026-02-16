package main

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

func TestMineBlock_WinningTimestampMustMatchPoWHeaderBytes(t *testing.T) {
	// This is intentionally a "real PoW" test: it uses the production Argon2id
	// PoW and reproduces the miner's behavior of mutating timestamp bytes in the
	// serialized header during nonce search.
	//
	// The historical bug was: the winning nonce was copied back to the returned
	// block header, but the winning timestamp (used in the header bytes that
	// actually satisfied PoW) was not. That produces a block object whose header
	// does not validate against its own nonce.
	if testing.Short() {
		t.Skip("skipping real PoW test in -short mode")
	}

	now := time.Now().Unix()
	header := BlockHeader{
		Version:    1,
		Height:     1,
		PrevHash:   sha3.Sum256([]byte("prev")),
		MerkleRoot: sha3.Sum256([]byte("merkle")),
		Timestamp:  now,
		Difficulty: MinDifficulty,
		Nonce:      0,
	}

	origHeaderBytes := header.SerializeForPoW()
	mutatedHeaderBytes := make([]byte, len(origHeaderBytes))
	copy(mutatedHeaderBytes, origHeaderBytes)

	winningTimestamp := now + 10
	// Timestamp starts at byte offset 76 in SerializeForPoW() (see miner.go).
	binary.LittleEndian.PutUint64(mutatedHeaderBytes[76:84], uint64(winningTimestamp))

	target := DifficultyToTarget(header.Difficulty)

	// Find a nonce that passes PoW for the mutated timestamp, but fails PoW for
	// the original timestamp. This makes the regression deterministic: if the
	// miner forgets to copy back the winning timestamp, the returned header must
	// fail PoW with the winning nonce.
	var winningNonce uint64
	found := false
	const maxNonces = 200
	for nonce := uint64(0); nonce < maxNonces; nonce++ {
		mutHash, err := PowHash(mutatedHeaderBytes, nonce)
		if err != nil || !PowCheckTarget(mutHash, target) {
			continue
		}
		origHash, err := PowHash(origHeaderBytes, nonce)
		if err != nil || PowCheckTarget(origHash, target) {
			continue
		}
		winningNonce = nonce
		found = true
		break
	}
	if !found {
		t.Fatalf("failed to find suitable nonce within %d attempts", maxNonces)
	}

	header.Nonce = winningNonce
	if validatePoW(&header) {
		t.Fatalf("expected PoW to fail when nonce=%d is paired with stale timestamp=%d", winningNonce, header.Timestamp)
	}

	header.Timestamp = winningTimestamp
	if !validatePoW(&header) {
		t.Fatalf("expected PoW to pass when nonce=%d is paired with winning timestamp=%d", winningNonce, winningTimestamp)
	}
}

