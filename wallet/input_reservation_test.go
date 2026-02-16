package wallet

import (
	"sync"
	"testing"
	"time"
)

func TestInputReservationLease_PreventsConcurrentSelectionAndReleases(t *testing.T) {
	w := &Wallet{
		inputReservations: make(map[reservedOutpoint]inputReservation),
	}

	var txid [32]byte
	txid[0] = 0xBB

	// Single mature output: any concurrent reservation for a target <= Amount
	// must contend for the same outpoint.
	w.data.Outputs = []*OwnedOutput{
		{
			TxID:        txid,
			OutputIndex: 0,
			Amount:      100,
			BlockHeight: 1,
			IsCoinbase:  false,
			Spent:       false,
		},
	}

	currentHeight := uint64(100)

	start := make(chan struct{})
	type res struct {
		lease  uint64
		inputs []*OwnedOutput
		err    error
	}
	out := make(chan res, 2)

	tryReserve := func() {
		<-start
		lease, inputs, err := w.ReserveMatureInputs(currentHeight, 50, 200*time.Millisecond)
		out <- res{lease: lease, inputs: inputs, err: err}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); tryReserve() }()
	go func() { defer wg.Done(); tryReserve() }()

	close(start)
	wg.Wait()

	r1 := <-out
	r2 := <-out

	successes := 0
	var success res
	if r1.err == nil {
		successes++
		success = r1
	}
	if r2.err == nil {
		successes++
		success = r2
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful reservation, got %d (err1=%v err2=%v)", successes, r1.err, r2.err)
	}
	if success.lease == 0 || len(success.inputs) != 1 {
		t.Fatalf("expected successful reservation to return 1 input and non-zero lease (lease=%d inputs=%d)", success.lease, len(success.inputs))
	}

	// Releasing the lease should allow reservation again immediately.
	w.ReleaseInputLease(success.lease)
	lease2, inputs2, err := w.ReserveMatureInputs(currentHeight, 50, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("expected reserve after release to succeed, got %v", err)
	}
	if lease2 == 0 || len(inputs2) != 1 {
		t.Fatalf("expected reserve after release to return 1 input and non-zero lease (lease=%d inputs=%d)", lease2, len(inputs2))
	}
	w.ReleaseInputLease(lease2)
}

func TestInputReservationLease_ExpiresByTTL(t *testing.T) {
	w := &Wallet{
		inputReservations: make(map[reservedOutpoint]inputReservation),
	}

	var txid [32]byte
	txid[0] = 0xCC

	w.data.Outputs = []*OwnedOutput{
		{
			TxID:        txid,
			OutputIndex: 1,
			Amount:      100,
			BlockHeight: 1,
			IsCoinbase:  false,
			Spent:       false,
		},
	}

	currentHeight := uint64(100)

	lease, _, err := w.ReserveMatureInputs(currentHeight, 50, 10*time.Millisecond)
	if err != nil || lease == 0 {
		t.Fatalf("expected initial reserve to succeed, lease=%d err=%v", lease, err)
	}

	// Without release, a second reservation should fail while TTL is active.
	lease2, _, err2 := w.ReserveMatureInputs(currentHeight, 50, 10*time.Millisecond)
	if err2 == nil || lease2 != 0 {
		t.Fatalf("expected reserve to fail while reserved; lease=%d err=%v", lease2, err2)
	}

	time.Sleep(20 * time.Millisecond)

	// After TTL, reservation should be purged and succeed.
	lease3, inputs3, err3 := w.ReserveMatureInputs(currentHeight, 50, 10*time.Millisecond)
	if err3 != nil || lease3 == 0 || len(inputs3) != 1 {
		t.Fatalf("expected reserve to succeed after TTL expiry; lease=%d inputs=%d err=%v", lease3, len(inputs3), err3)
	}
	w.ReleaseInputLease(lease3)
}

