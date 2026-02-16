package main

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestParseAmount_BoundariesOverflowAndPrecision(t *testing.T) {
	const atomicPerBNT = uint64(100_000_000)
	maxWhole := uint64(math.MaxUint64) / atomicPerBNT
	remainder := uint64(math.MaxUint64) % atomicPerBNT

	type tc struct {
		in      string
		want    uint64
		wantErr string
	}

	tests := []tc{
		{in: "0", want: 0},
		{in: "1", want: 1 * atomicPerBNT},
		{in: "1 BNT", want: 1 * atomicPerBNT},
		{in: "1.1", want: 1*atomicPerBNT + 10_000_000},
		{in: "1.00000000", want: 1 * atomicPerBNT},
		// Truncation (not rounding) beyond 8 decimals:
		{in: "1.000000009", want: 1 * atomicPerBNT},
		{in: "0.000000009", want: 0},
		// Max whole that doesn't overflow multiplication:
		{in: fmt.Sprintf("%d", maxWhole), want: maxWhole * atomicPerBNT},
		// Exact max uint64: maxWhole + remainder fractional.
		{in: fmt.Sprintf("%d.%08d", maxWhole, remainder), want: math.MaxUint64},
		// First overflowing whole (whole*atomicPerBNT):
		{in: fmt.Sprintf("%d", maxWhole+1), wantErr: "amount too large"},
		// Overflow on result+frac (frac > remainder):
		{in: fmt.Sprintf("%d.%08d", maxWhole, remainder+1), wantErr: "amount too large"},
		{in: "1.2.3", wantErr: "invalid amount format"},
	}

	for _, tt := range tests {
		got, err := parseAmount(tt.in)
		if tt.wantErr != "" {
			if err == nil {
				t.Fatalf("parseAmount(%q): expected error %q, got nil", tt.in, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseAmount(%q): unexpected error: %v", tt.in, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseAmount(%q): unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("parseAmount(%q): got %d, want %d", tt.in, got, tt.want)
		}
	}
}

