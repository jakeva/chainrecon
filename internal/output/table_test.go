package output

import (
	"strings"
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/model"
)

// sampleReport builds a fully-populated report for table formatting tests.
func sampleReport() *model.Report {
	return &model.Report{
		Package:         "lodash",
		Version:         "4.17.21",
		Timestamp:       time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		WeeklyDownloads: 103241892,
		DependentCount:  195000,
		Scores: model.Scores{
			Provenance:        2.0,
			PublishingHygiene: 6.5,
			MaintainerRisk:    4.0,
			IdentityStability: 7.0,
			BlastRadius:       9.8,
			AttackSurface:     5.7,
			TargetScore:       62.3,
		},
		Findings: []model.Finding{
			{Severity: model.SeverityCritical, Signal: "Provenance", Message: "No provenance attestation found"},
			{Severity: model.SeverityHigh, Signal: "Blast Radius", Message: "Extremely high weekly downloads"},
			{Severity: model.SeverityMedium, Signal: "Publishing Hygiene", Message: "Published by single maintainer"},
		},
	}
}

func TestTableFormatter_FormatCompleteReport(t *testing.T) {
	f := NewTableFormatter()
	out, err := f.Format(sampleReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	required := []string{
		"lodash",
		"4.17.21",
		"Provenance",
		"Publishing Hygiene",
		"Maintainer Risk",
		"Identity Stability",
		"Blast Radius",
		"Attack Surface",
		"Target Score",
		"2.0/10",
		"6.5/10",
		"4.0/10",
		"7.0/10",
		"9.8/10",
		"No provenance attestation found",
		"Extremely high weekly downloads",
		"Published by single maintainer",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("output missing expected string %q", s)
		}
	}
}

func TestTableFormatter_FormatZeroFindings(t *testing.T) {
	report := sampleReport()
	report.Findings = nil

	f := NewTableFormatter()
	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	if strings.Contains(out, "Key Findings") {
		t.Error("output should not contain Key Findings section when there are no findings")
	}
}

func TestTableFormatter_BoxDrawingCharacters(t *testing.T) {
	f := NewTableFormatter()
	out, err := f.Format(sampleReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	// Verify core box-drawing characters used in the table.
	for _, ch := range []string{"│", "─", "┌", "┐", "└", "┘", "┬", "┴", "├", "┤", "┼"} {
		if !strings.Contains(out, ch) {
			t.Errorf("output missing box-drawing character %q", ch)
		}
	}
}

func TestTableFormatter_DownloadFormatting(t *testing.T) {
	f := NewTableFormatter()
	out, err := f.Format(sampleReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	// 103241892 should be formatted as "103,241,892".
	if !strings.Contains(out, "103,241,892") {
		t.Errorf("output missing comma-formatted download count; got:\n%s", out)
	}
}

