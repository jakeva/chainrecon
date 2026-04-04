package analyzer

import (
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestNetworkAnalyzer(t *testing.T) {
	na := NewNetworkAnalyzer()

	tests := []struct {
		name         string
		diff         *model.ReleaseDiff
		wantCount    int
		wantSeverity model.Severity
		wantMessage  string
	}{
		{
			name: "no network calls",
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
			name: "require http in added file (high)",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/client.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const http = require('http');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  "New file introduces network access",
		},
		{
			name: "require https in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/fetch.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const https = require('https');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "require net in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/socket.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const net = require('net');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "require dgram in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/udp.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const dgram = require('dgram');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "require dns in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/resolve.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`const dns = require('dns');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "import from https in added .mjs",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/client.mjs",
					Status:     model.DiffAdded,
					NewContent: []byte(`import https from 'https';`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "fetch call in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/api.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`fetch("https://example.com/data");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "XMLHttpRequest in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/xhr.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`var xhr = new XMLHttpRequest();`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "net.Socket in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/conn.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`var s = new net.Socket();`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "net.connect in added file",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "lib/conn2.js",
					Status:     model.DiffAdded,
					NewContent: []byte(`net.connect(8080, 'localhost');`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name: "network added to previously non-networking file (high)",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "lib/util.js",
					Status:     model.DiffModified,
					OldContent: []byte(`function helper() { return 42; }`),
					NewContent: []byte(`const http = require('http'); function helper() { return 42; }`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityHigh,
			wantMessage:  "Network access introduced in previously non-networking file",
		},
		{
			name: "network modified in file that already had networking (medium)",
			diff: &model.ReleaseDiff{
				Modified: []model.FileDiff{{
					Path:       "lib/client.js",
					Status:     model.DiffModified,
					OldContent: []byte(`const http = require('http');`),
					NewContent: []byte(`const http = require('http'); fetch("https://evil.com");`),
				}},
			},
			wantCount:    1,
			wantSeverity: model.SeverityMedium,
			wantMessage:  "Network access patterns modified",
		},
		{
			name: "non-JS file is skipped",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "docs/api.md",
					Status:     model.DiffAdded,
					NewContent: []byte(`require('http')`),
				}},
			},
			wantCount: 0,
		},
		{
			name: ".ts file is scanned",
			diff: &model.ReleaseDiff{
				Added: []model.FileDiff{{
					Path:       "src/client.ts",
					Status:     model.DiffAdded,
					NewContent: []byte(`import http from 'http';`),
				}},
			},
			wantCount: 1,
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
				if f.Signal != "network_access" {
					t.Errorf("signal = %q, want network_access", f.Signal)
				}
			}
		})
	}
}
