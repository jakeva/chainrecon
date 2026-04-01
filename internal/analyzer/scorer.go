package analyzer

import (
	"math"

	"github.com/chainrecon/chainrecon/internal/model"
)

// Phase 1 weights for attack_surface_score (Section 3.2).
// Scorecard is excluded in Phase 1, so the remaining signals sum to 1.0.
const (
	weightProvenance       = 0.30
	weightPublishHygiene   = 0.25
	weightMaintainerRisk   = 0.25
	weightIdentityStability = 0.20
)

// SignalInputs bundles the individual signal scores that feed into the
// composite scoring model.
type SignalInputs struct {
	Provenance        model.SignalScore
	PublishingHygiene model.SignalScore
	MaintainerRisk    model.SignalScore
	IdentityStability model.SignalScore
	BlastRadius       model.SignalScore
}

// Scorer computes composite scores from individual signal inputs and
// classifies the resulting risk level.
type Scorer interface {
	// ComputeScores calculates the attack surface score, blast radius score,
	// and target score from the provided signal inputs.
	ComputeScores(signals SignalInputs) model.Scores

	// ClassifyRisk maps a target score to a risk classification string:
	// "CRITICAL", "HIGH", "MEDIUM", or "LOW".
	ClassifyRisk(targetScore float64) string
}

// scorer is the default implementation of Scorer.
type scorer struct{}

// NewScorer returns a new Scorer that implements the Phase 1 scoring model.
func NewScorer() Scorer {
	return &scorer{}
}

// ComputeScores implements the Section 3.2 composite scoring model.
//
// attack_surface_score is a weighted average of Provenance, PublishingHygiene,
// MaintainerRisk, and IdentityStability (each 0.0-10.0). The result is
// 0.0-10.0.
//
// target_score = attack_surface_score * blast_radius_score, producing a value
// in the range 0.0-100.0.
func (s *scorer) ComputeScores(signals SignalInputs) model.Scores {
	attackSurface := weightProvenance*signals.Provenance.Score +
		weightPublishHygiene*signals.PublishingHygiene.Score +
		weightMaintainerRisk*signals.MaintainerRisk.Score +
		weightIdentityStability*signals.IdentityStability.Score

	attackSurface = math.Round(attackSurface*10) / 10

	targetScore := attackSurface * signals.BlastRadius.Score
	targetScore = math.Round(targetScore*10) / 10

	return model.Scores{
		Provenance:        signals.Provenance.Score,
		PublishingHygiene: signals.PublishingHygiene.Score,
		MaintainerRisk:    signals.MaintainerRisk.Score,
		IdentityStability: signals.IdentityStability.Score,
		ScorecardRepo:     0.0, // Phase 2
		BlastRadius:       signals.BlastRadius.Score,
		AttackSurface:     attackSurface,
		TargetScore:       targetScore,
	}
}

// ClassifyRisk returns the risk classification for the given target score.
//
//	>= 70.0 -> "CRITICAL"
//	>= 50.0 -> "HIGH"
//	>= 25.0 -> "MEDIUM"
//	<  25.0 -> "LOW"
func (s *scorer) ClassifyRisk(targetScore float64) string {
	switch {
	case targetScore >= 70.0:
		return "CRITICAL"
	case targetScore >= 50.0:
		return "HIGH"
	case targetScore >= 25.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
