package format

import "testing"

func TestCommas(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{103241892, "103,241,892"},
		{-5000, "-5,000"},
	}
	for _, tc := range tests {
		got := Commas(tc.input)
		if got != tc.want {
			t.Errorf("Commas(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
