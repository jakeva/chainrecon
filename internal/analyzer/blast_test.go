package analyzer

import (
	"math"
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestBlastRadiusAnalyzer(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()
	const tolerance = 0.1

	tests := []struct {
		name            string
		weeklyDownloads int
		dependentCount  int
		packageName     string
		wantMinScore    float64
		wantMaxScore    float64
		wantSeverity    model.Severity
	}{
		{
			name:            "zero downloads score 0.0",
			weeklyDownloads: 0,
			dependentCount:  0,
			packageName:     "empty-pkg",
			wantMinScore:    0.0,
			wantMaxScore:    0.1,
			wantSeverity:    model.SeverityLow,
		},
		{
			name:            "500 downloads score 1.0",
			weeklyDownloads: 500,
			dependentCount:  0,
			packageName:     "small-pkg",
			wantMinScore:    0.9,
			wantMaxScore:    1.1,
			wantSeverity:    model.SeverityLow,
		},
		{
			name:            "50M+ downloads score 10.0",
			weeklyDownloads: 50_000_000,
			dependentCount:  0,
			packageName:     "mega-pkg",
			wantMinScore:    9.9,
			wantMaxScore:    10.0,
			wantSeverity:    model.SeverityCritical,
		},
		{
			name:            "100K downloads moderate score",
			weeklyDownloads: 100_000,
			dependentCount:  0,
			packageName:     "moderate-pkg",
			wantMinScore:    4.0,
			wantMaxScore:    6.0,
			wantSeverity:    model.SeverityMedium,
		},
		{
			name:            "security tooling package gets multiplier",
			weeklyDownloads: 100_000,
			dependentCount:  0,
			packageName:     "eslint-plugin-custom",
			wantMinScore:    7.0,
			wantMaxScore:    10.0,
			wantSeverity:    model.SeverityCritical,
		},
		{
			name:            "package with 50K+ dependents gets bonus",
			weeklyDownloads: 1_000_000,
			dependentCount:  60_000,
			packageName:     "popular-lib",
			wantMinScore:    7.0,
			wantMaxScore:    10.0,
			wantSeverity:    model.SeverityHigh,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, findings := ba.Analyze(tc.weeklyDownloads, tc.dependentCount, tc.packageName)

			if signal.Name != "blast_radius" {
				t.Errorf("signal name = %q, want %q", signal.Name, "blast_radius")
			}

			if signal.Score < tc.wantMinScore-tolerance || signal.Score > tc.wantMaxScore+tolerance {
				t.Errorf("Analyze(%d, %d, %q) score = %.2f, want between %.1f and %.1f",
					tc.weeklyDownloads, tc.dependentCount, tc.packageName,
					signal.Score, tc.wantMinScore, tc.wantMaxScore)
			}

			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}

			if findings[0].Severity != tc.wantSeverity {
				t.Errorf("finding severity = %q, want %q", findings[0].Severity, tc.wantSeverity)
			}

			if findings[0].Signal != "blast_radius" {
				t.Errorf("finding signal = %q, want %q", findings[0].Signal, "blast_radius")
			}
		})
	}
}

func TestBlastRadiusAnalyzer_CRITICAL_FindingForHighScore(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	signal, findings := ba.Analyze(50_000_000, 100_000, "ultra-popular-lib")

	if signal.Score < 9.0 {
		t.Errorf("expected score >= 9.0 for extreme popularity, got %.2f", signal.Score)
	}

	foundCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("expected CRITICAL finding for score >= 9.0")
	}
}

func TestBlastRadiusAnalyzer_SecurityToolingMultiplier(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	// Use a moderate download count so the multiplier effect is visible.
	baseSignal, _ := ba.Analyze(100_000, 0, "regular-lib")
	secSignal, _ := ba.Analyze(100_000, 0, "eslint-config-custom")

	if secSignal.Score <= baseSignal.Score {
		t.Errorf("security tooling score %.2f should be greater than base score %.2f",
			secSignal.Score, baseSignal.Score)
	}
}

func TestBlastRadiusAnalyzer_CICDMultiplier(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	baseSignal, _ := ba.Analyze(100_000, 0, "regular-lib")
	ciSignal, _ := ba.Analyze(100_000, 0, "webpack-plugin-custom")

	if ciSignal.Score <= baseSignal.Score {
		t.Errorf("CI/CD tooling score %.2f should be greater than base score %.2f",
			ciSignal.Score, baseSignal.Score)
	}
}

func TestBlastRadiusAnalyzer_DependentBonus(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	tests := []struct {
		name           string
		dependents     int
		wantMinBonus   float64
	}{
		{"no dependents no bonus", 0, 0.0},
		{"500 dependents no bonus", 500, 0.0},
		{"5000 dependents small bonus", 5000, 0.5},
		{"15000 dependents medium bonus", 15000, 1.0},
		{"60000 dependents large bonus", 60000, 1.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseSignal, _ := ba.Analyze(10_000, 0, "test-lib")
			bonusSignal, _ := ba.Analyze(10_000, tc.dependents, "test-lib")

			actualBonus := bonusSignal.Score - baseSignal.Score
			if math.Abs(actualBonus-tc.wantMinBonus) > 0.1 {
				t.Errorf("dependent bonus for %d dependents = %.2f, want ~%.1f",
					tc.dependents, actualBonus, tc.wantMinBonus)
			}
		})
	}
}

func TestBlastRadiusAnalyzer_ScoreCappedAt10(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	// Combine maximum downloads, max dependents, and security tooling multiplier.
	signal, _ := ba.Analyze(100_000_000, 100_000, "eslint-super-scanner")

	if signal.Score > 10.0 {
		t.Errorf("score = %.2f, must not exceed 10.0", signal.Score)
	}
}

func TestBlastRadiusAnalyzer_NegativeDownloads(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	signal, _ := ba.Analyze(-100, 0, "negative-pkg")

	if signal.Score != 0.0 {
		t.Errorf("negative downloads score = %.2f, want 0.0", signal.Score)
	}
}

func TestBlastRadiusAnalyzer_LogarithmicScaling(t *testing.T) {
	ba := NewBlastRadiusAnalyzer()

	// Verify the score increases with downloads on a logarithmic curve.
	prev := 0.0
	downloads := []int{1_000, 10_000, 100_000, 1_000_000, 10_000_000, 50_000_000}
	for _, d := range downloads {
		signal, _ := ba.Analyze(d, 0, "scaling-test")
		if signal.Score < prev {
			t.Errorf("score should increase monotonically: %d downloads = %.2f, previous = %.2f",
				d, signal.Score, prev)
		}
		prev = signal.Score
	}
}
