package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func SectionHead(label string, noColor bool) string {
	if noColor {
		return "# " + label
	}
	return "\033[38;2;170;255;0m#\033[0m " + label
}

func ErrorHead(label string, noColor bool) string {
	if noColor {
		return "# " + label
	}
	return "\033[38;2;255;0;170m#\033[0m " + label
}

func WarnHead(label string, noColor bool) string {
	if noColor {
		return "# " + label
	}
	return "\033[38;2;255;170;0m#\033[0m " + label
}

func FormatAmount(atomicUnits uint64) string {
	whole := atomicUnits / 100_000_000
	frac := atomicUnits % 100_000_000
	if frac == 0 {
		return fmt.Sprintf("%d BNT", whole)
	}
	fracStr := fmt.Sprintf("%08d", frac)
	fracStr = strings.TrimRight(fracStr, "0")
	return fmt.Sprintf("%d.%s BNT", whole, fracStr)
}

func ParseAmount(s string) (uint64, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "BNT")
	s = strings.TrimSpace(s)

	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid amount format")
	}

	var whole uint64
	if parts[0] != "" {
		var err error
		whole, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return 0, err
		}
	}

	const atomicPerBNT uint64 = 100_000_000
	if whole > (^uint64(0))/atomicPerBNT {
		return 0, fmt.Errorf("amount too large")
	}
	result := whole * atomicPerBNT

	if len(parts) == 2 {
		fracStr := parts[1]
		if len(fracStr) > 8 {
			fracStr = fracStr[:8]
		} else {
			fracStr += strings.Repeat("0", 8-len(fracStr))
		}
		frac, err := strconv.ParseUint(fracStr, 10, 64)
		if err != nil {
			return 0, err
		}
		if result > (^uint64(0))-frac {
			return 0, fmt.Errorf("amount too large")
		}
		result += frac
	}

	return result, nil
}

func FormatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// SanitizeInput strips non-printable ASCII from user input (fixes
// tmux/terminal copy-paste artifacts).
func SanitizeInput(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, s)
}
