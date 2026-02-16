package main

import (
	"math"
	"strings"
	"testing"
)

func TestTxBuilderBuild_RejectsUint64Overflows(t *testing.T) {
	t.Run("inputSumOverflow", func(t *testing.T) {
		b := NewTxBuilder()
		b.AddInput(&OwnedOutput{Amount: math.MaxUint64})
		b.AddInput(&OwnedOutput{Amount: 1})
		b.AddOutput([32]byte{}, [32]byte{}, 0)

		_, err := b.Build(nil)
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "input amount sum overflows uint64") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("outputSumOverflow", func(t *testing.T) {
		b := NewTxBuilder()
		b.AddInput(&OwnedOutput{Amount: 0})
		b.AddOutput([32]byte{}, [32]byte{}, math.MaxUint64)
		b.AddOutput([32]byte{}, [32]byte{}, 1)

		_, err := b.Build(nil)
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "output amount sum overflows uint64") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("outputPlusFeeOverflow", func(t *testing.T) {
		b := NewTxBuilder()
		b.AddInput(&OwnedOutput{Amount: 0})
		b.AddOutput([32]byte{}, [32]byte{}, math.MaxUint64)
		b.SetFee(1)

		_, err := b.Build(nil)
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "output amount + fee overflows uint64") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

