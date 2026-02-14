package wallet

func (w *Wallet) recordMemoDecryptFailure(blockHeight uint64) {
	w.memoDecryptFailures.Add(1)
	w.memoDecryptLastHeight.Store(blockHeight)
}

// MemoDecryptFailureCount returns the number of memo decrypt/validation failures
// observed while scanning owned outputs.
func (w *Wallet) MemoDecryptFailureCount() uint64 {
	return w.memoDecryptFailures.Load()
}

// MemoDecryptLastFailureHeight returns the block height of the most recent memo
// decrypt/validation failure (0 if none observed).
func (w *Wallet) MemoDecryptLastFailureHeight() uint64 {
	return w.memoDecryptLastHeight.Load()
}

