package analyzer

import (
	"math"
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestScoreCodeFindings_Empty(t *testing.T) {
	score := ScoreCodeFindings(nil)
	if score != 0.0 {
		t.Errorf("expected 0.0 for nil findings, got %.1f", score)
	}

	score = ScoreCodeFindings([]model.CodeFinding{})
	if score != 0.0 {
		t.Errorf("expected 0.0 for empty findings, got %.1f", score)
	}
}

func TestScoreCodeFindings_SingleSeverities(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     float64
	}{
		{model.SeverityCritical, 3.0},
		{model.SeverityHigh, 2.0},
		{model.SeverityMedium, 1.0},
		{model.SeverityLow, 0.5},
		{model.SeverityInfo, 0.0},
	}

	for _, tt := range tests {
		findings := []model.CodeFinding{{Severity: tt.severity, Signal: "test"}}
		got := ScoreCodeFindings(findings)
		if got != tt.want {
			t.Errorf("severity %s: got %.1f, want %.1f", tt.severity, got, tt.want)
		}
	}
}

func TestScoreCodeFindings_Additive(t *testing.T) {
	findings := []model.CodeFinding{
		{Severity: model.SeverityCritical, Signal: "lifecycle_script"},
		{Severity: model.SeverityHigh, Signal: "obfuscation"},
		{Severity: model.SeverityMedium, Signal: "network"},
	}
	// 3.0 + 2.0 + 1.0 = 6.0
	got := ScoreCodeFindings(findings)
	if got != 6.0 {
		t.Errorf("expected 6.0, got %.1f", got)
	}
}

func TestScoreCodeFindings_CappedAt10(t *testing.T) {
	findings := []model.CodeFinding{
		{Severity: model.SeverityCritical, Signal: "a"},
		{Severity: model.SeverityCritical, Signal: "b"},
		{Severity: model.SeverityCritical, Signal: "c"},
		{Severity: model.SeverityCritical, Signal: "d"},
	}
	// 3.0 * 4 = 12.0, capped to 10.0
	got := ScoreCodeFindings(findings)
	if got != 10.0 {
		t.Errorf("expected cap at 10.0, got %.1f", got)
	}
}

func TestCombineScores_NoFindings(t *testing.T) {
	base := model.Scores{
		AttackSurface: 5.0,
		BlastRadius:   4.0,
		TargetScore:   20.0,
	}

	result := CombineScores(base, nil)
	if result.CodeRisk != 0.0 {
		t.Errorf("expected code risk 0.0, got %.1f", result.CodeRisk)
	}
	if result.AdjustedTarget != 20.0 {
		t.Errorf("expected adjusted target 20.0 (unchanged), got %.1f", result.AdjustedTarget)
	}
	if result.RiskLevel != "LOW" {
		t.Errorf("expected LOW risk, got %s", result.RiskLevel)
	}
}

func TestCombineScores_WithFindings(t *testing.T) {
	base := model.Scores{
		AttackSurface: 6.0,
		BlastRadius:   7.0,
		TargetScore:   42.0,
	}

	findings := []model.CodeFinding{
		{Severity: model.SeverityCritical, Signal: "lifecycle_script"},
		{Severity: model.SeverityHigh, Signal: "obfuscation"},
	}

	result := CombineScores(base, findings)
	// code_risk = 3.0 + 2.0 = 5.0
	if result.CodeRisk != 5.0 {
		t.Errorf("expected code risk 5.0, got %.1f", result.CodeRisk)
	}
	// adjusted = 42.0 * (1.0 + 5.0/10.0) = 42.0 * 1.5 = 63.0
	if result.AdjustedTarget != 63.0 {
		t.Errorf("expected adjusted target 63.0, got %.1f", result.AdjustedTarget)
	}
	if result.RiskLevel != "HIGH" {
		t.Errorf("expected HIGH risk, got %s", result.RiskLevel)
	}
}

func TestCombineScores_MaxCodeRisk(t *testing.T) {
	base := model.Scores{
		TargetScore: 40.0,
	}

	findings := []model.CodeFinding{
		{Severity: model.SeverityCritical, Signal: "a"},
		{Severity: model.SeverityCritical, Signal: "b"},
		{Severity: model.SeverityCritical, Signal: "c"},
		{Severity: model.SeverityCritical, Signal: "d"},
	}

	result := CombineScores(base, findings)
	if result.CodeRisk != 10.0 {
		t.Errorf("expected max code risk 10.0, got %.1f", result.CodeRisk)
	}
	// adjusted = 40.0 * (1.0 + 10.0/10.0) = 40.0 * 2.0 = 80.0
	if result.AdjustedTarget != 80.0 {
		t.Errorf("expected adjusted target 80.0, got %.1f", result.AdjustedTarget)
	}
	if result.RiskLevel != "CRITICAL" {
		t.Errorf("expected CRITICAL risk, got %s", result.RiskLevel)
	}
}

func TestCombineScores_RoundingPrecision(t *testing.T) {
	base := model.Scores{
		TargetScore: 33.3,
	}

	findings := []model.CodeFinding{
		{Severity: model.SeverityMedium, Signal: "test"},
		{Severity: model.SeverityLow, Signal: "test2"},
	}

	result := CombineScores(base, findings)
	// code_risk = 1.0 + 0.5 = 1.5
	// adjusted = 33.3 * (1 + 1.5/10) = 33.3 * 1.15 = 38.295 -> rounds to 38.3
	expected := math.Round(33.3*1.15*10) / 10
	if result.AdjustedTarget != expected {
		t.Errorf("expected %.1f, got %.1f", expected, result.AdjustedTarget)
	}
}
