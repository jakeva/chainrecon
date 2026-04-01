package analyzer

import (
	"math"
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestScorer_ComputeScores(t *testing.T) {
	s := NewScorer()
	const tolerance = 0.1

	tests := []struct {
		name               string
		signals            SignalInputs
		wantAttackSurface  float64
		wantTargetScore    float64
	}{
		{
			name: "all signals at 5.0",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Name: "provenance", Score: 5.0},
				PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 5.0},
				MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 5.0},
				IdentityStability: model.SignalScore{Name: "identity", Score: 5.0},
				BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 5.0},
			},
			// attack_surface = 0.30*5 + 0.25*5 + 0.25*5 + 0.20*5 = 5.0
			// target_score = 5.0 * 5.0 = 25.0
			wantAttackSurface: 5.0,
			wantTargetScore:   25.0,
		},
		{
			name: "all signals at 10.0",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Name: "provenance", Score: 10.0},
				PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 10.0},
				MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 10.0},
				IdentityStability: model.SignalScore{Name: "identity", Score: 10.0},
				BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 10.0},
			},
			// attack_surface = 0.30*10 + 0.25*10 + 0.25*10 + 0.20*10 = 10.0
			// target_score = 10.0 * 10.0 = 100.0
			wantAttackSurface: 10.0,
			wantTargetScore:   100.0,
		},
		{
			name: "all signals at 0.0",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Name: "provenance", Score: 0.0},
				PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 0.0},
				MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 0.0},
				IdentityStability: model.SignalScore{Name: "identity", Score: 0.0},
				BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 0.0},
			},
			wantAttackSurface: 0.0,
			wantTargetScore:   0.0,
		},
		{
			name: "mixed signals",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Name: "provenance", Score: 9.0},
				PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 8.0},
				MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 7.0},
				IdentityStability: model.SignalScore{Name: "identity", Score: 4.0},
				BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 6.0},
			},
			// attack_surface = 0.30*9 + 0.25*8 + 0.25*7 + 0.20*4 = 2.7 + 2.0 + 1.75 + 0.8 = 7.25
			// math.Round(72.5)/10 = 7.2 (banker's rounding: 72.5 rounds to even = 72)
			// target_score = 7.2 * 6.0 = 43.2
			wantAttackSurface: 7.2,
			wantTargetScore:   43.2,
		},
		{
			name: "high attack surface low blast radius",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Name: "provenance", Score: 10.0},
				PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 10.0},
				MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 10.0},
				IdentityStability: model.SignalScore{Name: "identity", Score: 10.0},
				BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 1.0},
			},
			// attack_surface = 10.0, target_score = 10.0 * 1.0 = 10.0
			wantAttackSurface: 10.0,
			wantTargetScore:   10.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scores := s.ComputeScores(tc.signals)

			if math.Abs(scores.AttackSurface-tc.wantAttackSurface) > tolerance {
				t.Errorf("AttackSurface = %.2f, want ~%.1f", scores.AttackSurface, tc.wantAttackSurface)
			}

			if math.Abs(scores.TargetScore-tc.wantTargetScore) > tolerance {
				t.Errorf("TargetScore = %.2f, want ~%.1f", scores.TargetScore, tc.wantTargetScore)
			}

			// Verify individual signal scores are propagated.
			if scores.Provenance != tc.signals.Provenance.Score {
				t.Errorf("Provenance = %.2f, want %.2f", scores.Provenance, tc.signals.Provenance.Score)
			}
			if scores.PublishingHygiene != tc.signals.PublishingHygiene.Score {
				t.Errorf("PublishingHygiene = %.2f, want %.2f", scores.PublishingHygiene, tc.signals.PublishingHygiene.Score)
			}
			if scores.MaintainerRisk != tc.signals.MaintainerRisk.Score {
				t.Errorf("MaintainerRisk = %.2f, want %.2f", scores.MaintainerRisk, tc.signals.MaintainerRisk.Score)
			}
			if scores.IdentityStability != tc.signals.IdentityStability.Score {
				t.Errorf("IdentityStability = %.2f, want %.2f", scores.IdentityStability, tc.signals.IdentityStability.Score)
			}
			if scores.BlastRadius != tc.signals.BlastRadius.Score {
				t.Errorf("BlastRadius = %.2f, want %.2f", scores.BlastRadius, tc.signals.BlastRadius.Score)
			}

			// ScorecardRepo should be 0.0 in Phase 1.
			if scores.ScorecardRepo != 0.0 {
				t.Errorf("ScorecardRepo = %.2f, want 0.0 (Phase 1)", scores.ScorecardRepo)
			}
		})
	}
}

func TestScorer_ClassifyRisk(t *testing.T) {
	s := NewScorer()

	tests := []struct {
		name        string
		targetScore float64
		wantRisk    string
	}{
		{"CRITICAL at 70.0", 70.0, "CRITICAL"},
		{"CRITICAL at 100.0", 100.0, "CRITICAL"},
		{"CRITICAL at 85.0", 85.0, "CRITICAL"},
		{"HIGH at 50.0", 50.0, "HIGH"},
		{"HIGH at 69.9", 69.9, "HIGH"},
		{"MEDIUM at 25.0", 25.0, "MEDIUM"},
		{"MEDIUM at 49.9", 49.9, "MEDIUM"},
		{"LOW at 24.9", 24.9, "LOW"},
		{"LOW at 0.0", 0.0, "LOW"},
		{"LOW at 10.0", 10.0, "LOW"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.ClassifyRisk(tc.targetScore)
			if got != tc.wantRisk {
				t.Errorf("ClassifyRisk(%.1f) = %q, want %q", tc.targetScore, got, tc.wantRisk)
			}
		})
	}
}

func TestScorer_WeightsSumToOne(t *testing.T) {
	// Verify that the Phase 1 weights sum to 1.0.
	p1Total := p1WeightProvenance + p1WeightPublishHygiene + p1WeightMaintainerRisk + p1WeightIdentityStability
	if math.Abs(p1Total-1.0) > 0.001 {
		t.Errorf("Phase 1 weights sum to %.4f, want 1.0", p1Total)
	}

	// Verify that the Phase 2 weights sum to 1.0.
	p2Total := p2WeightProvenance + p2WeightPublishHygiene + p2WeightMaintainerRisk + p2WeightIdentityStability + p2WeightScorecard
	if math.Abs(p2Total-1.0) > 0.001 {
		t.Errorf("Phase 2 weights sum to %.4f, want 1.0", p2Total)
	}
}

func TestScorer_ComputeScores_Rounding(t *testing.T) {
	s := NewScorer()

	// Use values that produce fractional intermediate results to verify rounding.
	signals := SignalInputs{
		Provenance:        model.SignalScore{Name: "provenance", Score: 3.0},
		PublishingHygiene: model.SignalScore{Name: "publishing_hygiene", Score: 7.0},
		MaintainerRisk:    model.SignalScore{Name: "maintainer_risk", Score: 2.0},
		IdentityStability: model.SignalScore{Name: "identity", Score: 9.0},
		BlastRadius:       model.SignalScore{Name: "blast_radius", Score: 4.0},
	}

	// attack_surface = 0.30*3 + 0.25*7 + 0.25*2 + 0.20*9 = 0.9 + 1.75 + 0.5 + 1.8 = 4.95
	// rounded to 5.0
	// target_score = 5.0 * 4.0 = 20.0
	scores := s.ComputeScores(signals)

	if math.Abs(scores.AttackSurface-5.0) > 0.1 {
		t.Errorf("AttackSurface = %.2f, want ~5.0 (after rounding)", scores.AttackSurface)
	}

	if math.Abs(scores.TargetScore-20.0) > 0.1 {
		t.Errorf("TargetScore = %.2f, want ~20.0", scores.TargetScore)
	}
}

func TestScorer_EndToEnd_RiskClassification(t *testing.T) {
	s := NewScorer()

	tests := []struct {
		name     string
		signals  SignalInputs
		wantRisk string
	}{
		{
			name: "low risk package",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Score: 1.0},
				PublishingHygiene: model.SignalScore{Score: 0.0},
				MaintainerRisk:    model.SignalScore{Score: 1.0},
				IdentityStability: model.SignalScore{Score: 0.0},
				BlastRadius:       model.SignalScore{Score: 2.0},
			},
			// attack_surface = 0.30*1 + 0.25*0 + 0.25*1 + 0.20*0 = 0.55 -> 0.6
			// target = 0.6 * 2.0 = 1.2 -> LOW
			wantRisk: "LOW",
		},
		{
			name: "critical risk package",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Score: 9.0},
				PublishingHygiene: model.SignalScore{Score: 8.0},
				MaintainerRisk:    model.SignalScore{Score: 10.0},
				IdentityStability: model.SignalScore{Score: 7.0},
				BlastRadius:       model.SignalScore{Score: 10.0},
			},
			// attack_surface = 0.30*9 + 0.25*8 + 0.25*10 + 0.20*7 = 2.7+2.0+2.5+1.4 = 8.6
			// target = 8.6 * 10.0 = 86.0 -> CRITICAL
			wantRisk: "CRITICAL",
		},
		{
			name: "medium risk package",
			signals: SignalInputs{
				Provenance:        model.SignalScore{Score: 5.0},
				PublishingHygiene: model.SignalScore{Score: 5.0},
				MaintainerRisk:    model.SignalScore{Score: 5.0},
				IdentityStability: model.SignalScore{Score: 5.0},
				BlastRadius:       model.SignalScore{Score: 5.0},
			},
			// attack_surface = 5.0, target = 25.0 -> MEDIUM
			wantRisk: "MEDIUM",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scores := s.ComputeScores(tc.signals)
			risk := s.ClassifyRisk(scores.TargetScore)
			if risk != tc.wantRisk {
				t.Errorf("risk = %q (target=%.1f), want %q", risk, scores.TargetScore, tc.wantRisk)
			}
		})
	}
}
