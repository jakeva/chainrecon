//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

// TestIntegration_ScanAxios runs a real scan against the axios package
// and validates that a scored report is produced with all expected fields.
//
// Run with: go test -tags=integration -v ./internal/cli/
func TestIntegration_ScanAxios(t *testing.T) {
	// Capture stdout by redirecting through the command.
	root := NewRootCmd()
	root.AddCommand(NewScanCmd())

	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"scan", "axios", "--format", "json", "--no-cache", "--depth", "10"})

	// Redirect stdout to capture output.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stdout = w

	if err := root.Execute(); err != nil {
		w.Close()
		os.Stdout = oldStdout
		t.Fatalf("scan command failed: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout

	// Read captured output.
	var output bytes.Buffer
	output.ReadFrom(r)

	// Parse the JSON report.
	var report model.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nraw output:\n%s", err, output.String())
	}

	// Validate the report has expected fields.
	if report.Package != "axios" {
		t.Errorf("expected package 'axios', got %q", report.Package)
	}

	if report.Version == "" {
		t.Error("expected a version, got empty string")
	}

	if report.Timestamp.IsZero() {
		t.Error("expected a non-zero timestamp")
	}

	// Validate all scores are in range.
	scores := []struct {
		name  string
		value float64
	}{
		{"provenance", report.Scores.Provenance},
		{"publishing_hygiene", report.Scores.PublishingHygiene},
		{"maintainer_risk", report.Scores.MaintainerRisk},
		{"identity_stability", report.Scores.IdentityStability},
		{"blast_radius", report.Scores.BlastRadius},
		{"attack_surface", report.Scores.AttackSurface},
	}

	for _, s := range scores {
		if s.value < 0 || s.value > 10.0 {
			t.Errorf("score %s = %.1f, want 0.0-10.0", s.name, s.value)
		}
	}

	if report.Scores.TargetScore < 0 || report.Scores.TargetScore > 100.0 {
		t.Errorf("target_score = %.1f, want 0.0-100.0", report.Scores.TargetScore)
	}

	// Axios should have significant blast radius (100M+ weekly downloads).
	if report.WeeklyDownloads < 1_000_000 {
		t.Errorf("expected axios to have >1M weekly downloads, got %d", report.WeeklyDownloads)
	}

	// Should have at least some findings.
	if len(report.Findings) == 0 {
		t.Error("expected at least one finding")
	}

	// Should have provenance history entries.
	if len(report.ProvenanceHistory) == 0 {
		t.Error("expected provenance history entries")
	}

	t.Logf("Scan completed: %s@%s", report.Package, report.Version)
	t.Logf("Target Score: %.1f (%s)", report.Scores.TargetScore, classifyRisk(report.Scores.TargetScore))
	t.Logf("Weekly Downloads: %d", report.WeeklyDownloads)
	t.Logf("Findings: %d", len(report.Findings))
	for _, f := range report.Findings {
		t.Logf("  [%s] %s", f.Severity, f.Message)
	}
}

func classifyRisk(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
