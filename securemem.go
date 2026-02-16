package main

import "crypto/sha256"

// wipeBytes best-effort zeroes a byte slice.
// This is not a guarantee in Go (copies may exist), but it reduces exposure windows.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func passwordHash(password []byte) [32]byte {
	return sha256.Sum256(password)
}

