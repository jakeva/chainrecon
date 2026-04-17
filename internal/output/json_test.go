package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jakeva/chainrecon/internal/model"
)

// sampleJSONReport builds a fully-populated report for JSON formatting tests.
func sampleJSONReport() *model.Report {
	return &model.Report{
		Package:         "express",
		Version:         "4.18.2",
		Timestamp:       time.Date(2026, 3, 1, 8, 30, 0, 0, time.UTC),
		WeeklyDownloads: 25000000,
		DependentCount:  70000,
		Scores: model.Scores{
			Provenance:        8.0,
			PublishingHygiene: 7.5,
			MaintainerRisk:    3.0,
			IdentityStability: 9.0,
			BlastRadius:       9.5,
			AttackSurface:     6.0,
			TargetScore:       55.0,
		},
		Findings: []model.Finding{
			{Severity: model.SeverityHigh, Signal: "Blast Radius", Message: "Very high weekly downloads", Detail: "25M downloads/week"},
			{Severity: model.SeverityLow, Signal: "Maintainer Risk", Message: "Multiple maintainers", Detail: "3 maintainers with publish access"},
		},
		ProvenanceHistory: []model.ProvenanceVersion{
			{Version: "4.18.2", State: model.ProvenanceActive, HasSLSA: true, HasPublish: true},
			{Version: "4.18.1", State: model.ProvenanceActive, HasSLSA: true, HasPublish: true},
		},
		Maintainers: []model.Maintainer{
			{Name: "dougwilson", Email: "doug@example.com"},
		},
	}
}

func TestJSONFormatter_RoundTrip(t *testing.T) {
	f := NewJSONFormatter()
	report := sampleJSONReport()

	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Verify key fields survive the round trip.
	if decoded.Package != report.Package {
		t.Errorf("Package = %q, want %q", decoded.Package, report.Package)
	}
	if decoded.Version != report.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, report.Version)
	}
	if decoded.WeeklyDownloads != report.WeeklyDownloads {
		t.Errorf("WeeklyDownloads = %d, want %d", decoded.WeeklyDownloads, report.WeeklyDownloads)
	}
	if decoded.Scores.TargetScore != report.Scores.TargetScore {
		t.Errorf("TargetScore = %f, want %f", decoded.Scores.TargetScore, report.Scores.TargetScore)
	}
	if len(decoded.Findings) != len(report.Findings) {
		t.Errorf("len(Findings) = %d, want %d", len(decoded.Findings), len(report.Findings))
	}
	if len(decoded.ProvenanceHistory) != len(report.ProvenanceHistory) {
		t.Errorf("len(ProvenanceHistory) = %d, want %d", len(decoded.ProvenanceHistory), len(report.ProvenanceHistory))
	}
	if len(decoded.Maintainers) != len(report.Maintainers) {
		t.Errorf("len(Maintainers) = %d, want %d", len(decoded.Maintainers), len(report.Maintainers))
	}
}

func TestJSONFormatter_ContainsExpectedFields(t *testing.T) {
	f := NewJSONFormatter()
	out, err := f.Format(sampleJSONReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	required := []string{
		`"package"`,
		`"version"`,
		`"scores"`,
		`"findings"`,
		`"provenance_history"`,
		`"weekly_downloads"`,
		`"dependent_count"`,
		`"express"`,
		`"4.18.2"`,
		`"severity"`,
		`"signal"`,
		`"message"`,
		`"target_score"`,
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("JSON output missing expected field %s", s)
		}
	}
}

func TestJSONFormatter_PrettyPrinted(t *testing.T) {
	f := NewJSONFormatter()
	out, err := f.Format(sampleJSONReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	lines := strings.Split(out, "\n")
	if len(lines) < 5 {
		t.Fatalf("expected multi-line output for pretty-printed JSON, got %d lines", len(lines))
	}

	// Verify two-space indentation is present on at least one line.
	foundIndent := false
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") {
			foundIndent = true
			break
		}
	}
	if !foundIndent {
		t.Error("expected two-space indentation in pretty-printed JSON output")
	}
}
