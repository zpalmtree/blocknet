package main

import "testing"

func TestShouldAllowMiningTemplateDuringSync(t *testing.T) {
	tests := []struct {
		name     string
		progress uint64
		target   uint64
		want     bool
	}{
		{
			name:     "not behind",
			progress: 100,
			target:   100,
			want:     true,
		},
		{
			name:     "one block behind",
			progress: 99,
			target:   100,
			want:     true,
		},
		{
			name:     "tolerance boundary",
			progress: 98,
			target:   100,
			want:     true,
		},
		{
			name:     "beyond tolerance",
			progress: 97,
			target:   100,
			want:     false,
		},
		{
			name:     "zero target",
			progress: 0,
			target:   0,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAllowMiningTemplateDuringSync(tt.progress, tt.target); got != tt.want {
				t.Fatalf("got %v, want %v (progress=%d target=%d)", got, tt.want, tt.progress, tt.target)
			}
		})
	}
}
