package analyzer

import (
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestScorecardAnalyzer_NilResult(t *testing.T) {
	a := NewScorecardAnalyzer()
	score, findings := a.Analyze(nil)

	if score.Score != 5.0 {
		t.Errorf("nil result score = %.1f, want 5.0 (neutral)", score.Score)
	}
	if len(findings) != 1 {
		t.Fatalf("nil result findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("nil result severity = %s, want INFO", findings[0].Severity)
	}
}

func TestScorecardAnalyzer_GoodScore(t *testing.T) {
	a := NewScorecardAnalyzer()
	result := &model.ScorecardResult{
		Score: 8.5,
		Checks: []model.ScorecardCheck{
			{Name: "Branch-Protection", Score: 9, Reason: "branch protection enabled"},
			{Name: "Dangerous-Workflow", Score: 10, Reason: "no dangerous workflows"},
		},
	}

	score, _ := a.Analyze(result)

	// Inverted: 10 - 8.5 = 1.5
	if score.Score != 1.5 {
		t.Errorf("inverted score = %.1f, want 1.5", score.Score)
	}
}

func TestScorecardAnalyzer_BadScore(t *testing.T) {
	a := NewScorecardAnalyzer()
	result := &model.ScorecardResult{
		Score: 2.0,
		Checks: []model.ScorecardCheck{
			{Name: "Dangerous-Workflow", Score: 0, Reason: "uses pull_request_target"},
			{Name: "Pinned-Dependencies", Score: 2, Reason: "unpinned actions"},
			{Name: "Irrelevant-Check", Score: 1, Reason: "should be ignored"},
		},
	}

	score, findings := a.Analyze(result)

	// Inverted: 10 - 2.0 = 8.0
	if score.Score != 8.0 {
		t.Errorf("inverted score = %.1f, want 8.0", score.Score)
	}

	// Should have critical individual check findings for Dangerous-Workflow and Pinned-Dependencies.
	highFindings := 0
	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			highFindings++
		}
	}
	// 1 overall HIGH + 2 individual check HIGHs = 3
	if highFindings < 2 {
		t.Errorf("expected at least 2 HIGH findings for bad checks, got %d", highFindings)
	}
}

func TestScorecardAnalyzer_ScoreWithScorecard(t *testing.T) {
	s := NewScorer()
	scorecardScore := model.SignalScore{Name: "scorecard", Score: 4.0}

	scores := s.ComputeScores(SignalInputs{
		Provenance:        model.SignalScore{Score: 5.0},
		PublishingHygiene: model.SignalScore{Score: 5.0},
		MaintainerRisk:    model.SignalScore{Score: 5.0},
		IdentityStability: model.SignalScore{Score: 5.0},
		BlastRadius:       model.SignalScore{Score: 5.0},
		Scorecard:         &scorecardScore,
	})

	// Phase 2 weights with scorecard at 4.0:
	// 0.255*5 + 0.2125*5 + 0.2125*5 + 0.17*5 + 0.15*4 = 1.275+1.0625+1.0625+0.85+0.6 = 4.85 -> 4.8
	if scores.AttackSurface < 4.7 || scores.AttackSurface > 4.9 {
		t.Errorf("AttackSurface = %.2f, want ~4.8", scores.AttackSurface)
	}

	if scores.ScorecardRepo != 4.0 {
		t.Errorf("ScorecardRepo = %.1f, want 4.0", scores.ScorecardRepo)
	}
}
