package analyzer

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestNativeAddonAnalyzer(t *testing.T) {
	na := NewNativeAddonAnalyzer()

	tests := []struct {
		name         string
		diff         *model.ReleaseDiff
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name: "no binary files",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "index.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`module.exports = {};`),
				}},
			},
			wantCount: 0,
		},
		{
			name: "new .node file without previous (critical)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "build/Release/addon.node",
					Status:     model.DiffAdded,
					NewContent: []byte{0x00, 0x01},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
			wantMessage:  "Binary file addon.node added",
		},
		{
			name: "new .node file with existing .node (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "build/Release/new_addon.node",
					Status:     model.DiffAdded,
					NewContent: []byte{0x00},
				}},
				Modified: []model.FileDiff{{
					Path:       "build/Release/old_addon.node",
					Status:     model.DiffModified,
					OldContent: []byte{0x01},
					NewContent: []byte{0x02},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "new binding.gyp without previous (critical)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "binding.gyp",
					Status:     model.DiffAdded,
					NewContent: []byte(`{"targets": []}`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
			wantMessage:  "binding.gyp added to package",
		},
		{
			name: "new binding.gyp with existing one in modified (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "sub/binding.gyp",
					Status:     model.DiffAdded,
					NewContent: []byte(`{}`),
				}},
				Modified: []model.FileDiff{{
					Path:       "binding.gyp",
					Status:     model.DiffModified,
					OldContent: []byte(`{"old": true}`),
					NewContent: []byte(`{"new": true}`),
				}},
			},
			// Two findings: one for the added binding.gyp (high because old one exists),
			// and one for the modified binding.gyp.
			wantCount: 2,
		},
		{
			name: "modified binding.gyp (high)",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "binding.gyp",
					Status:     model.DiffModified,
					OldContent: []byte(`{"old": true}`),
					NewContent: []byte(`{"new": true}`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  "binding.gyp was modified",
		},
		{
			name: "new .so file (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/native.so",
					Status:     model.DiffAdded,
					NewContent: []byte{0x7f, 0x45, 0x4c, 0x46},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "new .dll file (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "bin/module.dll",
					Status:     model.DiffAdded,
					NewContent: []byte{0x4d, 0x5a},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "new .dylib file (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/native.dylib",
					Status:     model.DiffAdded,
					NewContent: []byte{0xfe, 0xed},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "new .wasm file (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/module.wasm",
					Status:     model.DiffAdded,
					NewContent: []byte{0x00, 0x61, 0x73, 0x6d},
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "removed .node file produces no findings",
			diff: &model.ReleaseDiff{
				Removed: []model.FileDiff{{
					Path:       "build/Release/addon.node",
					Status:     model.DiffRemoved,
					OldContent: []byte{0x00},
				}},
			},
			wantCount: 0,
		},
		{
			name: "multiple binaries added",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{
					{Path: "build/addon.node", Status: model.DiffAdded, NewContent: []byte{0x00}},
					{Path: "lib/native.so", Status: model.DiffAdded, NewContent: []byte{0x00}},
					{Path: "binding.gyp", Status: model.DiffAdded, NewContent: []byte(`{}`)},
				},
			},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := na.Analyze(tt.diff)

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
				if f.Signal != "native_addon" {
					t.Errorf("signal = %q, want native_addon", f.Signal)
				}
			}
		})
	}
}

func TestFileExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"build/addon.node", ".node"},
		{"lib/native.so", ".so"},
		{"index.js", ".js"},
		{"noext", ""},
		{"path/to/file.dylib", ".dylib"},
	}
	for _, tt := range tests {
		got := fileExt(tt.path)
		if got != tt.want {
			t.Errorf("fileExt(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestFileBase(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"build/Release/addon.node", "addon.node"},
		{"binding.gyp", "binding.gyp"},
		{"a/b/c/file.js", "file.js"},
	}
	for _, tt := range tests {
		got := fileBase(tt.path)
		if got != tt.want {
			t.Errorf("fileBase(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
