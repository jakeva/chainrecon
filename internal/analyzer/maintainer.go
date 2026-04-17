// Package analyzer implements the security analysis signals for chainrecon.
package analyzer

import (
	"fmt"
	"strings"

	"github.com/jakeva/chainrecon/internal/model"
)

// MaintainerAnalyzer evaluates the risk posed by the concentration and
// characteristics of a package's npm maintainers.
type MaintainerAnalyzer interface {
	// Analyze inspects maintainer metadata and returns a risk score
	// along with any security findings.
	Analyze(metadata *model.PackageMetadata) (model.SignalScore, []model.Finding)
}

// maintainerAnalyzer is the default implementation of MaintainerAnalyzer.
type maintainerAnalyzer struct{}

// NewMaintainerAnalyzer returns a MaintainerAnalyzer that evaluates maintainer
// concentration risk.
func NewMaintainerAnalyzer() MaintainerAnalyzer {
	return &maintainerAnalyzer{}
}

// Analyze examines maintainer count, bus factor, email domains, and package
// scope to produce a composite risk score from 1.0 (low risk) to 10.0 (high risk).
func (a *maintainerAnalyzer) Analyze(metadata *model.PackageMetadata) (model.SignalScore, []model.Finding) {
	var findings []model.Finding

	maintainerCount := len(metadata.Maintainers)

	// --- Maintainer count component (0-4 points) ---
	var countScore float64
	switch {
	case maintainerCount <= 1:
		countScore = 4.0
	case maintainerCount == 2:
		countScore = 2.5
	case maintainerCount <= 4:
		countScore = 1.5
	default:
		countScore = 0.5
	}

	// --- Bus factor component (0-3 points) ---
	busScore, topPublisher, topPct := computeBusFactor(metadata)

	// --- Email domain component (0-2 points) ---
	emailScore, allPersonal := computeEmailScore(metadata.Maintainers)

	// --- Scope component (0-1 point) ---
	scoped := strings.HasPrefix(metadata.Name, "@")
	var scopeScore float64
	if !scoped {
		scopeScore = 1.0
	}

	total := countScore + busScore + emailScore + scopeScore
	if total > 10.0 {
		total = 10.0
	}
	if total < 1.0 {
		total = 1.0
	}

	// --- Findings ---
	if maintainerCount == 1 {
		emailType := "organizational"
		if len(metadata.Maintainers) > 0 && isPersonalEmail(metadata.Maintainers[0].Email) {
			emailType = "personal"
		}
		name := "unknown"
		if len(metadata.Maintainers) > 0 {
			name = metadata.Maintainers[0].Name
		}
		findings = append(findings, model.Finding{
			Severity: model.SeverityCritical,
			Signal:   "maintainer_risk",
			Message:  "Single maintainer with full publish access",
			Detail:   fmt.Sprintf("Sole maintainer: %s (%s email)", name, emailType),
		})
	}

	if allPersonal && maintainerCount > 0 {
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "maintainer_risk",
			Message:  "All maintainers using personal email addresses",
			Detail: fmt.Sprintf(
				"%d maintainer(s) all using personal email domains",
				maintainerCount,
			),
		})
	}

	if topPct > 80.0 {
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "maintainer_risk",
			Message:  "Single publisher responsible for >80% of versions",
			Detail: fmt.Sprintf(
				"%s published %.0f%% of all versions",
				topPublisher, topPct,
			),
		})
	}

	if !scoped && maintainerCount >= 1 && maintainerCount <= 2 {
		findings = append(findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "maintainer_risk",
			Message:  "Unscoped package with limited maintainer access",
			Detail: fmt.Sprintf(
				"Unscoped package %q has only %d maintainer(s)",
				metadata.Name, maintainerCount,
			),
		})
	}

	detail := fmt.Sprintf(
		"maintainers=%d bus_factor=%.0f%% personal_email=%v scoped=%v",
		maintainerCount, topPct, allPersonal, scoped,
	)

	score := model.SignalScore{
		Name:   "maintainer_risk",
		Score:  total,
		Detail: detail,
	}

	return score, findings
}

// computeBusFactor determines the bus factor score by finding the publisher
// who published the most versions and calculating what percentage of all
// versions they account for. It returns the score component, the top
// publisher's name, and their percentage.
func computeBusFactor(metadata *model.PackageMetadata) (float64, string, float64) {
	publishCounts := make(map[string]int)

	for _, v := range metadata.Versions {
		if v.NPMUser != nil && v.NPMUser.Name != "" {
			publishCounts[v.NPMUser.Name]++
		}
	}

	totalVersions := len(metadata.Versions)
	if totalVersions == 0 {
		return 0.5, "", 0.0
	}

	var topPublisher string
	var topCount int
	for name, count := range publishCounts {
		if count > topCount || (count == topCount && name < topPublisher) {
			topCount = count
			topPublisher = name
		}
	}

	topPct := float64(topCount) / float64(totalVersions) * 100.0

	var busScore float64
	switch {
	case topPct > 80.0:
		busScore = 3.0
	case topPct > 50.0:
		busScore = 2.0
	default:
		busScore = 0.5
	}

	return busScore, topPublisher, topPct
}

// computeEmailScore evaluates whether maintainers are using personal or
// organizational email addresses. It returns the score component and whether
// all maintainers use personal email.
func computeEmailScore(maintainers []model.Maintainer) (float64, bool) {
	if len(maintainers) == 0 {
		return 0.0, false
	}

	personalCount := 0
	for _, m := range maintainers {
		if isPersonalEmail(m.Email) {
			personalCount++
		}
	}

	allPersonal := personalCount == len(maintainers)

	switch {
	case allPersonal:
		return 2.0, true
	case personalCount > 0:
		return 1.0, false
	default:
		return 0.0, false
	}
}

// isPersonalEmail reports whether the given email address belongs to a
// known personal email provider (e.g. gmail.com, protonmail.com).
func isPersonalEmail(email string) bool {
	return model.IsPersonalEmail(email)
}
