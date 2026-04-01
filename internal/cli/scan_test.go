package cli

import "testing"

func TestParsePackageArg(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"axios", "axios", ""},
		{"axios@1.14.0", "axios", "1.14.0"},
		{"@anthropic-ai/claude-code", "@anthropic-ai/claude-code", ""},
		{"@anthropic-ai/claude-code@1.0.0", "@anthropic-ai/claude-code", "1.0.0"},
		{"@scope/pkg@latest", "@scope/pkg", "latest"},
		{"lodash@4.17.21", "lodash", "4.17.21"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parsePackageArg(tt.input)
			if name != tt.wantName {
				t.Errorf("parsePackageArg(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("parsePackageArg(%q) version = %q, want %q", tt.input, version, tt.wantVersion)
			}
		})
	}
}
