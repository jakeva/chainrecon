package analyzer

import (
	"fmt"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// ScorecardAnalyzer evaluates a package's repository security posture
// using imported OpenSSF Scorecard data.
type ScorecardAnalyzer interface {
	// Analyze converts a Scorecard result into a chainrecon signal score.
	// The Scorecard score is inverted (10 - score) so that higher = more
	// vulnerable, matching chainrecon's convention. Returns a neutral
	// score if result is nil (repo not scored).
	Analyze(result *model.ScorecardResult) (model.SignalScore, []model.Finding)
}

type scorecardAnalyzer struct{}

// NewScorecardAnalyzer returns a new ScorecardAnalyzer.
func NewScorecardAnalyzer() ScorecardAnalyzer {
	return &scorecardAnalyzer{}
}

// Supply chain relevant checks we extract from the Scorecard result.
var relevantCheckSet = map[string]bool{
	"Dangerous-Workflow":  true,
	"Token-Permissions":   true,
	"Pinned-Dependencies": true,
	"Branch-Protection":   true,
	"Signed-Releases":     true,
}

// Analyze converts a Scorecard result into a chainrecon signal score.
func (s *scorecardAnalyzer) Analyze(result *model.ScorecardResult) (model.SignalScore, []model.Finding) {
	if result == nil {
		return model.SignalScore{
			Name:   "scorecard",
			Score:  5.0,
			Detail: "Repository not scored by OpenSSF Scorecard",
		}, []model.Finding{
			{
				Severity: model.SeverityInfo,
				Signal:   "scorecard",
				Message:  "No Scorecard data available",
				Detail:   "Repository has not been scored by OpenSSF Scorecard",
			},
		}
	}

	// Invert: Scorecard 10 = good, chainrecon 10 = bad.
	inverted := 10.0 - result.Score
	if inverted < 0 {
		inverted = 0
	}

	// Single pass over checks: build detail strings and flag critical checks.
	var checkDetails []string
	var findings []model.Finding

	// Overall finding first.
	severity := model.SeverityInfo
	switch {
	case inverted >= 7.0:
		severity = model.SeverityHigh
	case inverted >= 4.0:
		severity = model.SeverityMedium
	case inverted >= 2.0:
		severity = model.SeverityLow
	}

	findings = append(findings, model.Finding{
		Severity: severity,
		Signal:   "scorecard",
		Message:  fmt.Sprintf("OpenSSF Scorecard: %.1f/10", result.Score),
		Detail:   fmt.Sprintf("Imported from scorecard.dev (inverted to %.1f for scoring)", inverted),
	})

	for _, check := range result.Checks {
		if !relevantCheckSet[check.Name] || check.Score < 0 {
			continue
		}
		checkDetails = append(checkDetails, fmt.Sprintf("%s: %d/10", check.Name, check.Score))
		if check.Score <= 2 {
			findings = append(findings, model.Finding{
				Severity: model.SeverityHigh,
				Signal:   "scorecard",
				Message:  fmt.Sprintf("Scorecard %s: %d/10", check.Name, check.Score),
				Detail:   check.Reason,
			})
		}
	}

	detail := fmt.Sprintf("Scorecard %.1f/10 (inverted to %.1f)", result.Score, inverted)
	if len(checkDetails) > 0 {
		detail = fmt.Sprintf("%s | %s", detail, strings.Join(checkDetails, ", "))
	}

	signalScore := model.SignalScore{
		Name:   "scorecard",
		Score:  inverted,
		Detail: detail,
	}

	return signalScore, findings
}
