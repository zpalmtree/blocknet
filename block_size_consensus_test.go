package main

import (
	"bytes"
	"strings"
	"testing"

	"blocknet/wallet"
)

func TestTransactionSizeMatchesSerializeLength(t *testing.T) {
	// Build a tx with a realistic shape (variable proof/sig sizes, fixed memo bytes).
	ringMembers := make([][32]byte, RingSize)
	ringCommitments := make([][32]byte, RingSize)
	ringSig := make([]byte, 96+64*RingSize)
	for i := range ringSig {
		ringSig[i] = 0xAB
	}

	var memo [wallet.MemoSize]byte
	memo[0] = 0x01 // non-zero sentinel (not required for Serialize/Size, but keeps it realistic)

	tx := &Transaction{
		Version:     1,
		TxPublicKey: [32]byte{0x11},
		Fee:         123,
		Inputs: []TxInput{
			{
				KeyImage:        [32]byte{0x22},
				PseudoOutput:    [32]byte{0x33},
				RingMembers:     ringMembers,
				RingCommitments: ringCommitments,
				RingSignature:   ringSig,
			},
		},
		Outputs: []TxOutput{
			{
				PublicKey:       [32]byte{0x44},
				Commitment:      [32]byte{0x55},
				EncryptedAmount: [8]byte{0x66},
				EncryptedMemo:   memo,
				RangeProof:      bytes.Repeat([]byte{0x77}, 712),
			},
		},
	}

	serialized := tx.Serialize()
	if got, want := tx.Size(), len(serialized); got != want {
		t.Fatalf("tx.Size() drifted from Serialize(): got %d want %d", got, want)
	}
}

func TestBlockSizeMatchesCanonicalTxBytesAndIncludesMemo(t *testing.T) {
	base := &Transaction{
		Version:     1,
		TxPublicKey: [32]byte{0xAA},
		Fee:         0,
		Inputs:      nil,
		Outputs: []TxOutput{
			{
				PublicKey:       [32]byte{0xBB},
				Commitment:      [32]byte{0xCC},
				EncryptedAmount: [8]byte{0xDD},
				EncryptedMemo:   [wallet.MemoSize]byte{0x01},
				RangeProof:      nil,
			},
		},
	}

	// Adding a second output should increase canonical size by a predictable amount,
	// including the fixed 128-byte memo bytes.
	withTwo := &Transaction{
		Version:     base.Version,
		TxPublicKey: base.TxPublicKey,
		Fee:         base.Fee,
		Inputs:      nil,
		Outputs: append(append([]TxOutput(nil), base.Outputs...),
			TxOutput{
				PublicKey:       [32]byte{0xBE},
				Commitment:      [32]byte{0xEF},
				EncryptedAmount: [8]byte{0x01},
				EncryptedMemo:   [wallet.MemoSize]byte{0x02},
			},
		),
	}

	delta := len(withTwo.Serialize()) - len(base.Serialize())
	wantDelta := 32 + 32 + 8 + wallet.MemoSize + 4 // + proof bytes (0)
	if delta != wantDelta {
		t.Fatalf("unexpected tx size delta for added output: got %d want %d", delta, wantDelta)
	}

	blk := &Block{
		Header:       BlockHeader{Version: 1}, // header bytes are fixed-size in Size()
		Transactions: []*Transaction{base, withTwo},
	}

	wantBlockSize := blockHeaderSerializedSize + len(base.Serialize()) + len(withTwo.Serialize())
	if got := blk.Size(); got != wantBlockSize {
		t.Fatalf("block.Size() drifted from canonical tx bytes: got %d want %d", got, wantBlockSize)
	}
}

func TestBlockCheapPrefilterRejectsOversizeBlock_SizeIncludesMemoBytes(t *testing.T) {
	// Construct a block whose size exceeds MaxBlockSize only because of the
	// fixed memo bytes per output, then ensure the daemon cheap prefilter rejects it.
	coinbase := &Transaction{
		Version: 1,
		Inputs:  nil,
		Outputs: []TxOutput{{EncryptedMemo: [wallet.MemoSize]byte{0x01}}},
	}

	// Find an output count where:
	// - with memo bytes included: block is too large
	// - without memo bytes: block would be within the cap (i.e. memo is decisive)
	var blk *Block
	var oversizedTx *Transaction
	for outCount := 1; outCount < 20000; outCount += 50 {
		outputs := make([]TxOutput, outCount)
		for i := range outputs {
			outputs[i].EncryptedMemo[0] = 0x01
		}
		oversizedTx = &Transaction{
			Version: 1,
			Fee:     1,
			Inputs:  []TxInput{{}}, // non-coinbase
			Outputs: outputs,
		}
		blk = &Block{
			Header:       BlockHeader{Version: 1},
			Transactions: []*Transaction{coinbase, oversizedTx},
		}
		if blk.Size() > MaxBlockSize {
			// Subtract the memo bytes to approximate the buggy pre-memo accounting.
			sizeWithoutMemo := blk.Size() - wallet.MemoSize*(len(coinbase.Outputs)+len(oversizedTx.Outputs))
			if sizeWithoutMemo <= MaxBlockSize {
				break
			}
		}
	}
	if blk == nil || blk.Size() <= MaxBlockSize {
		t.Fatal("failed to construct an oversize block")
	}
	sizeWithoutMemo := blk.Size() - wallet.MemoSize*(len(coinbase.Outputs)+len(oversizedTx.Outputs))
	if sizeWithoutMemo > MaxBlockSize {
		t.Fatalf("failed to make memo bytes decisive: sizeWithoutMemo=%d sizeWithMemo=%d cap=%d", sizeWithoutMemo, blk.Size(), MaxBlockSize)
	}

	err := validateBlockCheapPrefilters(blk)
	if err == nil {
		t.Fatal("expected cheap prefilter to reject oversize block")
	}
	if !strings.Contains(err.Error(), "block too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

