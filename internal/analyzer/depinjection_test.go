package analyzer

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestDepInjectionAnalyzer(t *testing.T) {
	da := NewDepInjectionAnalyzer()

	tests := []struct {
		name         string
		oldPkg       map[string]any
		newPkg       map[string]any
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name:      "no dependencies in either version",
			oldPkg:    map[string]any{},
			newPkg:    map[string]any{},
			wantCount: 0,
		},
		{
			name:   "new runtime dependency added (high)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"dependencies": map[string]any{
					"evil-pkg": "^1.0.0",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  `New runtime dependency "evil-pkg" added`,
		},
		{
			name:   "new optional dependency (medium)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"optionalDependencies": map[string]any{
					"better-sqlite3": "^9.0.0",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  `New optional dependency "better-sqlite3" added`,
		},
		{
			name:   "new dev dependency (low)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"devDependencies": map[string]any{
					"jest": "^29.0.0",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityLow,
			wantMessage:  `New dev dependency "jest" added`,
		},
		{
			name:   "new peer dependency (low)",
			oldPkg: map[string]any{},
			newPkg: map[string]any{
				"peerDependencies": map[string]any{
					"react": "^18.0.0",
				},
			},
			wantCount:    1,
			wantSeverity: model.SeverityLow,
		},
		{
			name: "existing dependency unchanged produces no findings",
			oldPkg: map[string]any{
				"dependencies": map[string]any{
					"lodash": "^4.17.0",
				},
			},
			newPkg: map[string]any{
				"dependencies": map[string]any{
					"lodash": "^4.17.21",
				},
			},
			wantCount: 0,
		},
		{
			name: "dependency removed produces no findings",
			oldPkg: map[string]any{
				"dependencies": map[string]any{
					"lodash": "^4.17.0",
				},
			},
			newPkg:    map[string]any{},
			wantCount: 0,
		},
		{
			name: "multiple new deps across categories",
			oldPkg: map[string]any{
				"dependencies": map[string]any{
					"express": "^4.0.0",
				},
			},
			newPkg: map[string]any{
				"dependencies": map[string]any{
					"express":  "^4.0.0",
					"evil-pkg": "^1.0.0",
				},
				"devDependencies": map[string]any{
					"jest": "^29.0.0",
				},
			},
			wantCount: 2,
		},
		{
			name:      "nil old package.json",
			oldPkg:    nil,
			newPkg:    map[string]any{"dependencies": map[string]any{"foo": "^1.0.0"}},
			wantCount: 1,
		},
		{
			name:      "nil new package.json",
			oldPkg:    map[string]any{"dependencies": map[string]any{"foo": "^1.0.0"}},
			newPkg:    nil,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := &model.ReleaseDiff{
				OldPackageJSON: tt.oldPkg,
				NewPackageJSON: tt.newPkg,
			}

			findings := da.Analyze(diff)

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
				if f.Signal != "dependency_injection" {
					t.Errorf("signal = %q, want dependency_injection", f.Signal)
				}
			}
		})
	}
}
