package analyzer

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestTagCorrelationAnalyzer_AllMatched(t *testing.T) {
	a := NewTagCorrelationAnalyzer()
	versions := []string{"1.0.0", "1.1.0", "2.0.0"}
	releases := []model.GitHubRelease{
		{TagName: "v1.0.0"},
		{TagName: "v1.1.0"},
		{TagName: "v2.0.0"},
	}

	findings := a.Analyze(versions, releases)
	if len(findings) != 0 {
		t.Errorf("expected no findings when all versions match, got %d", len(findings))
	}
}

func TestTagCorrelationAnalyzer_SomeMissing(t *testing.T) {
	a := NewTagCorrelationAnalyzer()
	versions := []string{"2.0.0", "1.1.0", "1.0.0"}
	releases := []model.GitHubRelease{
		{TagName: "v1.0.0"},
	}

	findings := a.Analyze(versions, releases)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %s, want HIGH (latest version missing)", findings[0].Severity)
	}
}

func TestTagCorrelationAnalyzer_NoReleases(t *testing.T) {
	a := NewTagCorrelationAnalyzer()
	versions := []string{"1.0.0"}

	findings := a.Analyze(versions, nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings when no releases exist, got %d", len(findings))
	}
}

func TestTagCorrelationAnalyzer_NormalizesVPrefix(t *testing.T) {
	a := NewTagCorrelationAnalyzer()
	// npm version without v, GitHub tag with v.
	versions := []string{"1.0.0"}
	releases := []model.GitHubRelease{
		{TagName: "v1.0.0"},
	}

	findings := a.Analyze(versions, releases)
	if len(findings) != 0 {
		t.Errorf("v prefix normalization failed, got %d findings", len(findings))
	}
}

func TestTagCorrelationAnalyzer_FewMissing(t *testing.T) {
	a := NewTagCorrelationAnalyzer()
	// Only 1 missing, and it's not the latest.
	versions := []string{"2.0.0", "1.1.0", "1.0.0"}
	releases := []model.GitHubRelease{
		{TagName: "v2.0.0"},
		{TagName: "v1.0.0"},
	}

	findings := a.Analyze(versions, releases)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// Only 1 missing and it's not the latest, so LOW severity.
	if findings[0].Severity != model.SeverityLow {
		t.Errorf("severity = %s, want LOW (only 1 non-latest missing)", findings[0].Severity)
	}
}
