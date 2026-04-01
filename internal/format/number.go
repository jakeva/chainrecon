// Package format provides shared formatting utilities.
package format

import (
	"fmt"
	"strings"
)

// Commas formats an integer with comma-separated thousands (e.g. 1,234,567).
func Commas(n int) string {
	if n < 0 {
		return "-" + Commas(-n)
	}

	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var b strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		b.WriteString(s[:remainder])
	}
	for i := remainder; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}

	return b.String()
}
