package wallet

import (
	"math"
	"strings"
	"testing"
)

func TestBuilderTransfer_RejectsRecipientSumOverflow(t *testing.T) {
	// This should fail before touching b.wallet at all.
	b := &Builder{
		wallet: nil,
		config: TransferConfig{},
	}

	_, err := b.Transfer([]Recipient{
		{Amount: math.MaxUint64},
		{Amount: 1},
	}, 1, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "recipient amount sum overflows uint64") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuilderTransfer_RejectsSendPlusFeeOverflow(t *testing.T) {
	// This should fail before input selection (ReserveMatureInputs) runs.
	b := &Builder{
		wallet: nil,
		config: TransferConfig{
			MinFee: 1,
		},
	}

	_, err := b.Transfer([]Recipient{
		{Amount: math.MaxUint64},
	}, 1, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "send amount + fee overflows uint64") {
		t.Fatalf("unexpected error: %v", err)
	}
}

