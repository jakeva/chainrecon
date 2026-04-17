package analyzer

import (
	"math"

	"github.com/jakeva/chainrecon/internal/model"
)

// Severity weights for code findings when computing a composite code risk score.
const (
	codeWeightCritical = 3.0
	codeWeightHigh     = 2.0
	codeWeightMedium   = 1.0
	codeWeightLow      = 0.5
	codeWeightInfo     = 0.0

	// maxCodeRisk caps the code risk score at 10.0.
	maxCodeRisk = 10.0
)

// ContextualResult combines metadata-based scores with code analysis findings
// to produce an adjusted risk assessment.
type ContextualResult struct {
	BaseScores     model.Scores        `json:"base_scores"`
	CodeRisk       float64             `json:"code_risk"`
	AdjustedTarget float64             `json:"adjusted_target"`
	RiskLevel      string              `json:"risk_level"`
	CodeFindings   []model.CodeFinding `json:"code_findings"`
}

// ScoreCodeFindings computes a 0-10 risk score from code analysis findings.
// Each finding contributes a weight based on its severity:
//
//	CRITICAL: 3.0, HIGH: 2.0, MEDIUM: 1.0, LOW: 0.5, INFO: 0.0
//
// The score is capped at 10.0.
func ScoreCodeFindings(findings []model.CodeFinding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var score float64
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			score += codeWeightCritical
		case model.SeverityHigh:
			score += codeWeightHigh
		case model.SeverityMedium:
			score += codeWeightMedium
		case model.SeverityLow:
			score += codeWeightLow
		case model.SeverityInfo:
			score += codeWeightInfo
		}
	}

	return math.Min(score, maxCodeRisk)
}

// CombineScores takes metadata-based scores and code analysis findings and
// returns an adjusted risk assessment. The code risk acts as a multiplier
// on the target score:
//
//	adjusted_target = target_score * (1.0 + code_risk / 10.0)
//
// A clean diff (no findings) leaves the target score unchanged. Maximum code
// risk of 10.0 doubles the target score.
func CombineScores(base model.Scores, codeFindings []model.CodeFinding) *ContextualResult {
	codeRisk := ScoreCodeFindings(codeFindings)
	codeRisk = math.Round(codeRisk*10) / 10

	multiplier := 1.0 + codeRisk/maxCodeRisk
	adjustedTarget := base.TargetScore * multiplier
	adjustedTarget = math.Round(adjustedTarget*10) / 10

	return &ContextualResult{
		BaseScores:     base,
		CodeRisk:       codeRisk,
		AdjustedTarget: adjustedTarget,
		RiskLevel:      ClassifyRisk(adjustedTarget),
		CodeFindings:   codeFindings,
	}
}
