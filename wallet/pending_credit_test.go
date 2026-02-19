package wallet

import "testing"

func TestWallet_PendingUnconfirmedBalance_ClearsOnAddOutput(t *testing.T) {
	w := &Wallet{
		data: WalletData{Outputs: []*OwnedOutput{}},
	}

	var txID [32]byte
	txID[0] = 0x42

	w.AddPendingCredit(txID, 123)
	if got := w.PendingUnconfirmedBalance(); got != 123 {
		t.Fatalf("PendingUnconfirmedBalance()=%d, want %d", got, 123)
	}

	// Simulate the scanner discovering the expected credit in a confirmed block.
	w.AddOutput(&OwnedOutput{
		TxID:        txID,
		OutputIndex: 0,
		Amount:      123,
	})

	if got := w.PendingUnconfirmedBalance(); got != 0 {
		t.Fatalf("PendingUnconfirmedBalance() after AddOutput=%d, want %d", got, 0)
	}
}

