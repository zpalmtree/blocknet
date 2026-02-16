package wallet

import "testing"

func TestWalletOutputGetters_ReturnDeepCopiedSnapshots(t *testing.T) {
	w := &Wallet{
		inputReservations: make(map[reservedOutpoint]inputReservation),
	}

	var txid [32]byte
	txid[0] = 0xAA

	origMemo := []byte{0x01, 0x02, 0x03}
	w.data.Outputs = []*OwnedOutput{
		{
			TxID:        txid,
			OutputIndex: 7,
			Amount:      123,
			BlockHeight: 1,
			IsCoinbase:  false,
			Spent:       false,
			Memo:        append([]byte(nil), origMemo...),
		},
	}

	// 1) AllOutputs deep copy
	all1 := w.AllOutputs()
	if len(all1) != 1 {
		t.Fatalf("expected 1 output, got %d", len(all1))
	}
	all1[0].Amount = 999
	all1[0].Memo[0] = 0xFF

	all2 := w.AllOutputs()
	if len(all2) != 1 {
		t.Fatalf("expected 1 output, got %d", len(all2))
	}
	if all2[0].Amount != 123 {
		t.Fatalf("expected Amount unchanged in wallet, got %d", all2[0].Amount)
	}
	if all2[0].Memo[0] != 0x01 {
		t.Fatalf("expected Memo deep copy; got memo[0]=%x", all2[0].Memo[0])
	}

	// 2) SpendableOutputs deep copy
	sp1 := w.SpendableOutputs()
	if len(sp1) != 1 {
		t.Fatalf("expected 1 spendable output, got %d", len(sp1))
	}
	sp1[0].Memo[1] = 0xEE
	sp2 := w.SpendableOutputs()
	if sp2[0].Memo[1] != 0x02 {
		t.Fatalf("expected SpendableOutputs memo deep copy; got memo[1]=%x", sp2[0].Memo[1])
	}

	// 3) MatureOutputs respects maturity and deep copy
	immature := w.MatureOutputs(5) // confirmations < SafeConfirmations
	if len(immature) != 0 {
		t.Fatalf("expected 0 mature outputs at height 5, got %d", len(immature))
	}
	mature := w.MatureOutputs(50)
	if len(mature) != 1 {
		t.Fatalf("expected 1 mature output at height 50, got %d", len(mature))
	}
	mature[0].Memo[2] = 0xDD
	mature2 := w.MatureOutputs(50)
	if mature2[0].Memo[2] != 0x03 {
		t.Fatalf("expected MatureOutputs memo deep copy; got memo[2]=%x", mature2[0].Memo[2])
	}
}

