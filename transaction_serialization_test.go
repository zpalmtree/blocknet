package main

import (
	"encoding/binary"
	"blocknet/wallet"
	"strings"
	"testing"
)

func TestDeserializeTxRejectsTrailingBytes(t *testing.T) {
	tx := &Transaction{
		Version:     1,
		TxPublicKey: [32]byte{0xAA},
		Inputs:      nil,
		Outputs: []TxOutput{
			{
				PublicKey:       [32]byte{0xBB},
				Commitment:      [32]byte{0xCC},
				EncryptedAmount: [8]byte{0x01},
			},
		},
		Fee: 0,
	}

	canonical := tx.Serialize()
	withTrailing := append(append([]byte(nil), canonical...), 0xDE, 0xAD, 0xBE, 0xEF)

	_, err := DeserializeTx(withTrailing)
	if err == nil {
		t.Fatal("expected trailing-byte transaction to be rejected")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeserializeTxRejectsLegacyNoMemoWireShapeAndTruncatedMemo(t *testing.T) {
	build := func(memoLen int) []byte {
		// Minimal tx encoding with 0 inputs, 1 output, proofLen=0.
		// The only difference across variants is how many memo bytes appear in the output.
		size := 1 + 32 + 4 + 4 + 8 + (32 + 32 + 8 + memoLen + 4)
		buf := make([]byte, size)
		off := 0

		// Version
		buf[off] = 1
		off++

		// Tx public key
		for i := 0; i < 32; i++ {
			buf[off+i] = 0x11
		}
		off += 32

		// Input count (0)
		binary.LittleEndian.PutUint32(buf[off:], 0)
		off += 4

		// Output count (1)
		binary.LittleEndian.PutUint32(buf[off:], 1)
		off += 4

		// Fee (0)
		binary.LittleEndian.PutUint64(buf[off:], 0)
		off += 8

		// Output public key
		for i := 0; i < 32; i++ {
			buf[off+i] = 0x22
		}
		off += 32

		// Output commitment
		for i := 0; i < 32; i++ {
			buf[off+i] = 0x33
		}
		off += 32

		// Encrypted amount (8 bytes)
		for i := 0; i < 8; i++ {
			buf[off+i] = 0x44
		}
		off += 8

		// Encrypted memo (memoLen bytes; legacy shape uses 0 here)
		for i := 0; i < memoLen; i++ {
			buf[off+i] = 0x55
		}
		off += memoLen

		// Range proof length (0)
		binary.LittleEndian.PutUint32(buf[off:], 0)
		return buf
	}

	canonical := build(wallet.MemoSize)
	if _, err := DeserializeTx(canonical); err != nil {
		t.Fatalf("expected canonical memo wire shape to parse, got error: %v", err)
	}

	legacyNoMemo := build(0)
	if _, err := DeserializeTx(legacyNoMemo); err == nil {
		t.Fatal("expected legacy no-memo wire shape to be rejected")
	} else if !strings.Contains(err.Error(), "unexpected end of data in output") {
		t.Fatalf("unexpected error for legacy no-memo shape: %v", err)
	}

	truncatedMemo := build(wallet.MemoSize - 1)
	if _, err := DeserializeTx(truncatedMemo); err == nil {
		t.Fatal("expected truncated memo bytes to be rejected")
	} else if !strings.Contains(err.Error(), "unexpected end of data in output") {
		t.Fatalf("unexpected error for truncated memo shape: %v", err)
	}
}

func TestDeserializeTxRejectsOversizedRangeProofLen(t *testing.T) {
	// Minimal tx encoding with 0 inputs, 1 output, proofLen set above cap.
	const proofLen = 1025
	size := 1 + 32 + 4 + 4 + 8 + (32 + 32 + 8 + wallet.MemoSize + 4)
	buf := make([]byte, size)
	off := 0
	buf[off] = 1
	off++
	off += 32 // tx pubkey
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4 // input count
	binary.LittleEndian.PutUint32(buf[off:], 1)
	off += 4 // output count
	off += 8 // fee
	off += 32 + 32 + 8 + wallet.MemoSize
	binary.LittleEndian.PutUint32(buf[off:], proofLen)

	_, err := DeserializeTx(buf)
	if err == nil {
		t.Fatal("expected oversized range proof length to be rejected")
	}
	if !strings.Contains(err.Error(), "range proof size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeserializeTxRejectsOversizedRingSize(t *testing.T) {
	// Minimal tx with 1 input and ringSize just above the fixed RingSize cap.
	size := 1 + 32 + 4 + 4 + 8 + (32 + 32 + 4)
	buf := make([]byte, size)
	off := 0
	buf[off] = 1
	off++
	off += 32 // tx pubkey
	binary.LittleEndian.PutUint32(buf[off:], 1)
	off += 4 // input count
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4 // output count
	off += 8 // fee
	off += 32 + 32 // key_image + pseudo_output
	binary.LittleEndian.PutUint32(buf[off:], uint32(RingSize+1))

	_, err := DeserializeTx(buf)
	if err == nil {
		t.Fatal("expected oversized ring size to be rejected")
	}
	if !strings.Contains(err.Error(), "ring size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeserializeTxRejectsOversizedRingCTSignatureLen(t *testing.T) {
	// tx with 1 input, ringSize=RingSize, and sigLen set above cap (96+64*RingSize).
	ringSize := RingSize
	needed := ringSize * 32
	size := 1 + 32 + 4 + 4 + 8 + // header
		(32 + 32 + 4) + // key_image + pseudo_output + ring_size
		needed + // ring members
		needed + // ring commitments
		4 // sigLen

	buf := make([]byte, size)
	off := 0
	buf[off] = 1
	off++
	off += 32 // tx pubkey
	binary.LittleEndian.PutUint32(buf[off:], 1)
	off += 4 // input count
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4 // output count
	off += 8 // fee
	off += 32 + 32
	binary.LittleEndian.PutUint32(buf[off:], uint32(ringSize))
	off += 4
	off += needed + needed
	binary.LittleEndian.PutUint32(buf[off:], uint32(96+64*RingSize+1))

	_, err := DeserializeTx(buf)
	if err == nil {
		t.Fatal("expected oversized signature length to be rejected")
	}
	if !strings.Contains(err.Error(), "signature size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

