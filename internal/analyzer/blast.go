package analyzer

import (
	"fmt"
	"math"
	"strings"

	"github.com/chainrecon/chainrecon/internal/format"
	"github.com/chainrecon/chainrecon/internal/model"
)

// BlastRadiusAnalyzer evaluates the ecosystem impact of a compromised package
// by scoring its weekly download volume, dependent count, and ecosystem
// category.
type BlastRadiusAnalyzer interface {
	// Analyze computes a blast-radius signal score and associated findings
	// for the given package download count, dependent count, and name.
	Analyze(weeklyDownloads int, dependentCount int, packageName string) (model.SignalScore, []model.Finding)
}

// blastRadiusAnalyzer is the default implementation of BlastRadiusAnalyzer.
type blastRadiusAnalyzer struct{}

// NewBlastRadiusAnalyzer returns a new BlastRadiusAnalyzer ready for use.
func NewBlastRadiusAnalyzer() BlastRadiusAnalyzer {
	return &blastRadiusAnalyzer{}
}

// Ecosystem category multipliers.
const (
	multiplierSecurityTooling  = 2.0
	multiplierCICDTooling      = 1.5
	multiplierDeveloperTooling = 1.3
	multiplierRuntimeLibrary   = 1.0
)

// Scoring thresholds for the logarithmic download scale.
const (
	downloadsFloor   = 1000
	downloadsCeiling = 50_000_000
	scoreFloor       = 1.0
	scoreCeiling     = 10.0
)

// Pre-computed log10 values for the download score interpolation.
var (
	logFloor   = math.Log10(float64(downloadsFloor))
	logCeiling = math.Log10(float64(downloadsCeiling))
)

// Analyze computes the blast-radius score using a logarithmic scale over
// weekly downloads, applies an ecosystem category multiplier based on the
// package name, and adds a bonus for high dependent counts. The final score
// is capped at 10.0. Findings are generated at CRITICAL, HIGH, MEDIUM, or
// LOW severity depending on the final score.
func (b *blastRadiusAnalyzer) Analyze(weeklyDownloads int, dependentCount int, packageName string) (model.SignalScore, []model.Finding) {
	// Step 1: Compute base score from weekly downloads on a logarithmic scale.
	score := downloadScore(weeklyDownloads)

	// Step 2: Apply ecosystem category multiplier.
	multiplier := classifyCategory(packageName)
	score *= multiplier
	if score > scoreCeiling {
		score = scoreCeiling
	}

	// Step 3: Add dependent count bonus.
	score += dependentBonus(dependentCount)
	if score > scoreCeiling {
		score = scoreCeiling
	}

	detail := fmt.Sprintf("%s weekly downloads, %s direct dependents",
		format.Commas(weeklyDownloads), format.Commas(dependentCount))

	signalScore := model.SignalScore{
		Name:   "blast_radius",
		Score:  score,
		Detail: detail,
	}

	findings := buildBlastRadiusFindings(score, detail)

	return signalScore, findings
}

// downloadScore computes the base score from weekly download count using a
// logarithmic scale. Packages under 1K downloads score 1.0, packages over
// 50M downloads score 10.0, and everything in between is linearly
// interpolated on the log10 scale.
func downloadScore(downloads int) float64 {
	if downloads <= 0 {
		return 0.0
	}
	if downloads < downloadsFloor {
		return scoreFloor
	}
	if downloads >= downloadsCeiling {
		return scoreCeiling
	}

	// Linear interpolation on the log10 scale:
	// log10(1000)=3 -> 1.0, log10(50_000_000)~7.699 -> 10.0
	logVal := math.Log10(float64(downloads))

	return scoreFloor + (scoreCeiling-scoreFloor)*(logVal-logFloor)/(logCeiling-logFloor)
}

// classifyCategory returns the ecosystem category multiplier for a package
// based on name heuristics. Security tooling receives the highest multiplier
// because a compromise there undermines the detection layer itself.
func classifyCategory(packageName string) float64 {
	lower := strings.ToLower(packageName)

	// Security tooling: scanners, linters, audit tools.
	securityKeywords := []string{"eslint", "lint", "security", "scan", "audit", "snyk", "trivy"}
	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return multiplierSecurityTooling
		}
	}

	// CI/CD tooling: build tools, test frameworks.
	cicdKeywords := []string{
		"webpack", "babel", "rollup", "vite", "jest", "mocha",
		"cypress", "playwright", "turbo", "nx", "github-actions", "action",
	}
	for _, kw := range cicdKeywords {
		if strings.Contains(lower, kw) {
			return multiplierCICDTooling
		}
	}

	// Developer tooling: CLIs, formatters, TypeScript utilities.
	devKeywords := []string{"cli", "prettier", "format", "typescript", "ts-node"}
	for _, kw := range devKeywords {
		if strings.Contains(lower, kw) {
			return multiplierDeveloperTooling
		}
	}

	// Default: runtime library.
	return multiplierRuntimeLibrary
}

// dependentBonus returns additional score points based on the number of
// direct dependents. Heavily depended-upon packages receive a bonus because
// a single compromise propagates widely through the dependency graph.
func dependentBonus(dependents int) float64 {
	switch {
	case dependents > 50000:
		return 1.5
	case dependents > 10000:
		return 1.0
	case dependents > 1000:
		return 0.5
	default:
		return 0.0
	}
}

// buildBlastRadiusFindings produces findings based on the computed blast
// radius score, including download and dependent counts in the detail.
func buildBlastRadiusFindings(score float64, detail string) []model.Finding {
	var findings []model.Finding

	switch {
	case score >= 9.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityCritical,
			Signal:   "blast_radius",
			Message:  "Extremely high blast radius",
			Detail:   detail,
		})
	case score >= 7.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "blast_radius",
			Message:  "High blast radius",
			Detail:   detail,
		})
	case score >= 4.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "blast_radius",
			Message:  "Moderate blast radius",
			Detail:   detail,
		})
	default:
		findings = append(findings, model.Finding{
			Severity: model.SeverityLow,
			Signal:   "blast_radius",
			Message:  "Limited blast radius",
			Detail:   detail,
		})
	}

	return findings
}

