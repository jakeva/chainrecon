package analyzer

import (
	"math"

	"github.com/chainrecon/chainrecon/internal/model"
)

// Weights for attack_surface_score.
// When Scorecard data is available, it accounts for 15% and the other
// signals are scaled down proportionally.
const (
	// Base weights (no Scorecard, sum to 1.0).
	baseWeightProvenance        = 0.30
	baseWeightPublishHygiene    = 0.25
	baseWeightMaintainerRisk    = 0.25
	baseWeightIdentityStability = 0.20

	// Extended weights (with Scorecard, sum to 1.0).
	extWeightProvenance        = 0.255
	extWeightPublishHygiene    = 0.2125
	extWeightMaintainerRisk    = 0.2125
	extWeightIdentityStability = 0.17
	extWeightScorecard         = 0.15
)

// SignalInputs bundles the individual signal scores that feed into the
// composite scoring model.
type SignalInputs struct {
	Provenance        model.SignalScore
	PublishingHygiene model.SignalScore
	MaintainerRisk    model.SignalScore
	IdentityStability model.SignalScore
	BlastRadius       model.SignalScore
	Scorecard         *model.SignalScore // nil when Scorecard is unavailable/skipped
}

// Scorer computes composite scores from individual signal inputs.
type Scorer interface {
	// ComputeScores calculates the attack surface score, blast radius score,
	// and target score from the provided signal inputs.
	ComputeScores(signals SignalInputs) model.Scores
}

// scorer is the default implementation of Scorer.
type scorer struct{}

// NewScorer returns a new Scorer.
func NewScorer() Scorer {
	return &scorer{}
}

// ComputeScores implements the composite scoring model.
//
// When Scorecard data is available, it gets 15% weight and the other
// signals are scaled down proportionally. When unavailable, the base
// weights (summing to 1.0 across the four npm signals) are used.
//
// target_score = attack_surface_score * blast_radius_score
func (s *scorer) ComputeScores(signals SignalInputs) model.Scores {
	var attackSurface float64
	var scorecardScore float64

	if signals.Scorecard != nil {
		scorecardScore = signals.Scorecard.Score
		attackSurface = extWeightProvenance*signals.Provenance.Score +
			extWeightPublishHygiene*signals.PublishingHygiene.Score +
			extWeightMaintainerRisk*signals.MaintainerRisk.Score +
			extWeightIdentityStability*signals.IdentityStability.Score +
			extWeightScorecard*scorecardScore
	} else {
		attackSurface = baseWeightProvenance*signals.Provenance.Score +
			baseWeightPublishHygiene*signals.PublishingHygiene.Score +
			baseWeightMaintainerRisk*signals.MaintainerRisk.Score +
			baseWeightIdentityStability*signals.IdentityStability.Score
	}

	attackSurface = math.Round(attackSurface*10) / 10

	targetScore := attackSurface * signals.BlastRadius.Score
	targetScore = math.Round(targetScore*10) / 10

	return model.Scores{
		Provenance:        signals.Provenance.Score,
		PublishingHygiene: signals.PublishingHygiene.Score,
		MaintainerRisk:    signals.MaintainerRisk.Score,
		IdentityStability: signals.IdentityStability.Score,
		ScorecardRepo:     scorecardScore,
		BlastRadius:       signals.BlastRadius.Score,
		AttackSurface:     attackSurface,
		TargetScore:       targetScore,
	}
}

// ClassifyRisk maps a target score to a risk classification string.
func ClassifyRisk(targetScore float64) string {
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
