package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/model"
)

func sampleSARIFReport() *model.Report {
	return &model.Report{
		Package:         "lodash",
		Version:         "4.17.21",
		Timestamp:       time.Date(2026, 3, 1, 8, 30, 0, 0, time.UTC),
		WeeklyDownloads: 103000000,
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
			{Severity: model.SeverityCritical, Signal: "provenance", Message: "No provenance attestation found", Detail: "0 of 20 versions have provenance"},
			{Severity: model.SeverityHigh, Signal: "blast_radius", Message: "Extremely high weekly downloads"},
			{Severity: model.SeverityMedium, Signal: "publishing_hygiene", Message: "Published by single maintainer"},
			{Severity: model.SeverityLow, Signal: "maintainer_risk", Message: "Multiple maintainers"},
			{Severity: model.SeverityInfo, Signal: "identity", Message: "Stable publishing identity"},
		},
	}
}

func TestSARIFFormatter_ValidJSON(t *testing.T) {
	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(sampleSARIFReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestSARIFFormatter_SchemaAndVersion(t *testing.T) {
	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(sampleSARIFReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("missing SARIF version 2.1.0")
	}
	if !strings.Contains(out, "sarif-2.1.0.json") {
		t.Error("missing SARIF schema reference")
	}
}

func TestSARIFFormatter_ToolDriver(t *testing.T) {
	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(sampleSARIFReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	if !strings.Contains(out, `"name": "chainrecon"`) {
		t.Error("missing tool driver name")
	}
	if !strings.Contains(out, `"version": "0.2.0"`) {
		t.Error("missing tool driver version")
	}
}

func TestSARIFFormatter_ResultCount(t *testing.T) {
	f := NewSARIFFormatter("0.2.0")
	report := sampleSARIFReport()
	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if got := len(doc.Runs[0].Results); got != len(report.Findings) {
		t.Errorf("result count = %d, want %d", got, len(report.Findings))
	}
}

func TestSARIFFormatter_SeverityMapping(t *testing.T) {
	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(sampleSARIFReport())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	results := doc.Runs[0].Results
	expected := []string{"error", "error", "warning", "note", "note"}
	for i, want := range expected {
		if results[i].Level != want {
			t.Errorf("result[%d].Level = %q, want %q", i, results[i].Level, want)
		}
	}
}

func TestSARIFFormatter_SecuritySeverity(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     string
	}{
		{model.SeverityCritical, "9.0"},
		{model.SeverityHigh, "7.0"},
		{model.SeverityMedium, "4.0"},
		{model.SeverityLow, "2.0"},
		{model.SeverityInfo, "1.0"},
	}
	for _, tt := range tests {
		got := securitySeverity(tt.severity)
		if got != tt.want {
			t.Errorf("securitySeverity(%s) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSARIFFormatter_DeduplicatesRules(t *testing.T) {
	report := &model.Report{
		Package: "test-pkg",
		Version: "1.0.0",
		Findings: []model.Finding{
			{Severity: model.SeverityHigh, Signal: "provenance", Message: "Finding A"},
			{Severity: model.SeverityHigh, Signal: "provenance", Message: "Finding B"},
		},
	}

	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Both findings share the same signal+severity, so they should produce one rule.
	if got := len(doc.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Errorf("rule count = %d, want 1 (should deduplicate)", got)
	}
	// But both results should still be present.
	if got := len(doc.Runs[0].Results); got != 2 {
		t.Errorf("result count = %d, want 2", got)
	}
}

func TestSARIFFormatter_DetailAppended(t *testing.T) {
	report := &model.Report{
		Package: "test-pkg",
		Version: "1.0.0",
		Findings: []model.Finding{
			{Severity: model.SeverityHigh, Signal: "provenance", Message: "No provenance", Detail: "0 of 20 versions"},
		},
	}

	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	if !strings.Contains(out, "No provenance: 0 of 20 versions") {
		t.Error("result message should combine message and detail")
	}
}

func TestSARIFFormatter_EmptyFindings(t *testing.T) {
	report := &model.Report{
		Package:  "test-pkg",
		Version:  "1.0.0",
		Findings: nil,
	}

	f := NewSARIFFormatter("0.2.0")
	out, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got := len(doc.Runs[0].Results); got != 0 {
		t.Errorf("result count = %d, want 0 for empty findings", got)
	}
}
