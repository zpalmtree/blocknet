package wallet

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"fmt"

	"blocknet/protocol/params"
)

const (
	// Re-export protocol constants for wallet callers.
	// Consensus-critical code should import `blocknet/protocol/params` directly.
	MemoSize = params.MemoSize

	memoEnvelopeVersion = params.MemoEnvelopeVersion
	memoPayloadMax      = params.MemoPayloadMax
)

// EncryptMemo builds a memo envelope and encrypts it with a shared secret.
func EncryptMemo(memo []byte, sharedSecret [32]byte, outputIndex int) ([MemoSize]byte, error) {
	envelope, err := buildMemoEnvelope(memo)
	if err != nil {
		return [MemoSize]byte{}, err
	}
	mask := deriveMemoMask(sharedSecret, outputIndex)
	var encrypted [MemoSize]byte
	for i := range MemoSize {
		encrypted[i] = envelope[i] ^ mask[i]
	}
	return encrypted, nil
}

// DecryptMemo decrypts and validates a memo envelope.
// Returns (nil, true) for an empty memo payload.
func DecryptMemo(encrypted [MemoSize]byte, sharedSecret [32]byte, outputIndex int) ([]byte, bool) {
	mask := deriveMemoMask(sharedSecret, outputIndex)
	var plain [MemoSize]byte
	for i := range MemoSize {
		plain[i] = encrypted[i] ^ mask[i]
	}
	if plain[0] != memoEnvelopeVersion {
		return nil, false
	}
	length := int(plain[1])
	if length < 0 || length > memoPayloadMax {
		return nil, false
	}
	payload := plain[4 : 4+length]
	var expected [2]byte
	checksum := memoChecksum(payload)
	copy(expected[:], checksum[:2])
	if plain[2] != expected[0] || plain[3] != expected[1] {
		return nil, false
	}
	if length == 0 {
		return nil, true
	}
	out := make([]byte, length)
	copy(out, payload)
	return out, true
}

func buildMemoEnvelope(memo []byte) ([MemoSize]byte, error) {
	if len(memo) > memoPayloadMax {
		return [MemoSize]byte{}, fmt.Errorf("memo too long: max %d bytes", memoPayloadMax)
	}
	var envelope [MemoSize]byte
	envelope[0] = memoEnvelopeVersion
	envelope[1] = byte(len(memo))
	checksum := memoChecksum(memo)
	copy(envelope[2:4], checksum[:2])
	copy(envelope[4:], memo)

	// Use cryptographic random padding to make empty memos indistinguishable.
	padStart := 4 + len(memo)
	if padStart < MemoSize {
		// Fail closed: deterministic padding is observable and can leak
		// entropy-failure conditions into ciphertext distributions.
		n, err := rand.Read(envelope[padStart:])
		if err != nil {
			return [MemoSize]byte{}, fmt.Errorf("memo padding rng failure: %w", err)
		}
		if n != MemoSize-padStart {
			return [MemoSize]byte{}, fmt.Errorf("memo padding rng short read: got %d want %d", n, MemoSize-padStart)
		}
	}
	return envelope, nil
}

func memoChecksum(payload []byte) [32]byte {
	var payloadLen [2]byte
	binary.LittleEndian.PutUint16(payloadLen[:], uint16(len(payload)))
	const tag = "blocknet_memo_checksum"
	b := make([]byte, 0, len(tag)+len(payloadLen)+len(payload))
	b = append(b, tag...)
	b = append(b, payloadLen[:]...)
	b = append(b, payload...)
	return sha3.Sum256(b)
}

func deriveMemoMask(sharedSecret [32]byte, outputIndex int) [MemoSize]byte {
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	const tag = "memo"
	b := make([]byte, 0, 32+len(tag)+len(outputIndexBytes)+len(params.MemoBlockDomainSep))
	b = append(b, sharedSecret[:]...)
	b = append(b, tag...)
	b = append(b, outputIndexBytes[:]...)
	b = append(b, params.MemoBlockDomainSep...)
	seedSum := sha3.Sum256(b)
	seed := seedSum[:]

	var mask [MemoSize]byte
	for i := range 4 {
		var blockIndex [4]byte
		binary.LittleEndian.PutUint32(blockIndex[:], uint32(i))
		bi := make([]byte, 0, len(seed)+len(blockIndex))
		bi = append(bi, seed...)
		bi = append(bi, blockIndex[:]...)
		block := sha3.Sum256(bi)
		copy(mask[i*32:(i+1)*32], block[:])
	}
	return mask
}
