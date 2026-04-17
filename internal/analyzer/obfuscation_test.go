package analyzer

import (
	"strings"
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestObfuscationAnalyzer(t *testing.T) {
	oa := NewObfuscationAnalyzer()

	tests := []struct {
		name         string
		diff         *model.ReleaseDiff
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name: "clean JS file produces no findings",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "index.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`console.log("hello world");`),
				}},
			},
			wantCount: 0,
		},
		{
			name: "eval alone is medium",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/run.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`eval("console.log('hi')");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "eval() call detected",
		},
		{
			name: "eval with Buffer.from base64 is high",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/payload.js",
					Status: model.DiffAdded,
					NewContent: []byte(`
						var payload = Buffer.from("dGVzdA==", "base64");
						eval(payload.toString());
					`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "Buffer.from alone is medium",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/decode.js",
					Status: model.DiffAdded,
					NewContent: []byte(`
						var data = Buffer.from(encoded, "base64");
					`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "Buffer.from with base64/hex encoding detected",
		},
		{
			name: "hex payload detected",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/shell.js",
					Status: model.DiffAdded,
					NewContent: []byte(`var cmd = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21";`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "Hex encoded payload detected",
		},
		{
			name: "String.fromCharCode detected",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/gen.js",
					Status: model.DiffAdded,
					NewContent: []byte(`var s = String.fromCharCode(104, 101, 108, 108, 111);`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "String.fromCharCode usage detected",
		},
		{
			name: "high entropy string detected",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/token.js",
					Status: model.DiffAdded,
					NewContent: []byte(`var key = "` + highEntropyString(50) + `";`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "High entropy string detected",
		},
		{
			name: "non-JS file is skipped",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "readme.md",
					Status:     model.DiffAdded,
					NewContent: []byte(`eval("something")`),
				}},
			},
			wantCount: 0,
		},
		{
			name: "modified file uses NewContent",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "lib/util.mjs",
					Status:     model.DiffModified,
					OldContent: []byte(`export function noop() {}`),
					NewContent: []byte(`eval("pwned");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
		},
		{
			name: ".ts file is scanned",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "src/index.ts",
					Status:     model.DiffAdded,
					NewContent: []byte(`eval("ts code");`),
				}},
			},
			wantCount: 1,
		},
		{
			name: ".cjs file is scanned",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/util.cjs",
					Status:     model.DiffAdded,
					NewContent: []byte(`eval("cjs code");`),
				}},
			},
			wantCount: 1,
		},
		{
			name: "eval with hex payload is high",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/evil.js",
					Status: model.DiffAdded,
					NewContent: []byte(`
						var code = "\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67";
						eval(code);
					`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := oa.Analyze(tt.diff)

			if len(findings) != tt.wantCount {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantCount, findings)
			}

			if tt.wantCount > 0 && tt.wantSeverity != "" {
				if findings[0].Severity != tt.wantSeverity {
					t.Errorf("severity = %s, want %s", findings[0].Severity, tt.wantSeverity)
				}
			}

			if tt.wantMessage != "" && tt.wantCount > 0 {
				if findings[0].Message != tt.wantMessage {
					t.Errorf("message = %q, want %q", findings[0].Message, tt.wantMessage)
				}
			}

			for _, f := range findings {
				if f.Signal != "obfuscation" {
					t.Errorf("signal = %q, want obfuscation", f.Signal)
				}
			}
		})
	}
}

// highEntropyString generates a string with high Shannon entropy by cycling
// through a wide set of characters.
func highEntropyString(length int) string {
	chars := "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789!@#$%"
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteByte(chars[i%len(chars)])
	}
	return b.String()
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty string",
			input:   "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single repeated char",
			input:   "aaaaaaaaaa",
			wantMin: 0,
			wantMax: 0.01,
		},
		{
			name:    "two chars alternating",
			input:   "ababababab",
			wantMin: 0.9,
			wantMax: 1.1,
		},
		{
			name:    "high entropy random-looking string",
			input:   highEntropyString(50),
			wantMin: 4.5,
			wantMax: 7.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %f, want [%f, %f]", tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}
