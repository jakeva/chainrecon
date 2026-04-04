// Package analyzer implements the security analysis signals for chainrecon.
package analyzer

import (
	"fmt"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// HygieneAnalyzer evaluates the publishing hygiene of an npm package by
// inspecting attestation provenance, publisher identity, and whether trusted
// publishing is enforced.
type HygieneAnalyzer interface {
	// Analyze computes a publishing-hygiene signal score and associated
	// findings for the given package metadata and version attestations.
	Analyze(metadata *model.PackageMetadata, attestations []model.VersionAttestation) (model.SignalScore, []model.Finding)
}

// hygieneAnalyzer is the default implementation of HygieneAnalyzer.
type hygieneAnalyzer struct{}

// NewHygieneAnalyzer returns a new HygieneAnalyzer ready for use.
func NewHygieneAnalyzer() HygieneAnalyzer {
	return &hygieneAnalyzer{}
}

// Analyze inspects attestation records and publisher metadata to produce a
// publishing-hygiene risk score from 0.0 (trusted publishing fully enforced)
// to 10.0 (no provenance, direct human publish). It checks for:
//   - Trusted publishing enforcement via OIDC provenance
//   - Direct publish detection via the _npmUser field
//   - Mixed publishing methods across versions
//   - Single-maintainer risk
func (h *hygieneAnalyzer) Analyze(metadata *model.PackageMetadata, attestations []model.VersionAttestation) (model.SignalScore, []model.Finding) {
	score := 0.0
	var details []string

	// Build a lookup of attestations by version.
	attestByVersion := make(map[string]model.VersionAttestation, len(attestations))
	for _, a := range attestations {
		attestByVersion[a.Version] = a
	}

	// Count versions with and without provenance (trusted publishing).
	withProvenance := 0
	withoutProvenance := 0
	for _, a := range attestations {
		if a.HasSLSA && a.HasPublish {
			withProvenance++
		} else {
			withoutProvenance++
		}
	}

	// Determine the latest version from dist-tags if available.
	latestVersion := ""
	if metadata.DistTags != nil {
		latestVersion = metadata.DistTags["latest"]
	}

	// --- Check 1: No provenance at all ---
	if withProvenance == 0 {
		score += 5.0
		details = append(details, "no versions have provenance attestations")
	} else if latestVersion != "" {
		// --- Check 2: Latest version lost provenance ---
		if la, ok := attestByVersion[latestVersion]; ok {
			if (!la.HasSLSA || !la.HasPublish) && withProvenance > 0 {
				score += 3.0
				details = append(details, "latest version lacks provenance but older versions have it")
			}
		}
	}

	// --- Check 3: Latest version publisher appears to be human ---
	if latestVersion != "" {
		if vd, ok := metadata.Versions[latestVersion]; ok && vd.NPMUser != nil {
			if !isBotPublisher(vd.NPMUser.Name) {
				score += 2.0
				details = append(details, fmt.Sprintf("latest version published by human user %q", vd.NPMUser.Name))
			}
		}
	}

	// --- Check 4: Mixed publishing methods ---
	if withProvenance > 0 && withoutProvenance > 0 {
		score += 2.0
		details = append(details, fmt.Sprintf("mixed publishing methods: %d with provenance, %d without", withProvenance, withoutProvenance))
	}

	// --- Check 5: Single maintainer risk ---
	if len(metadata.Maintainers) == 1 {
		score += 1.0
		details = append(details, "single maintainer increases account compromise risk")
	}

	// Cap score at 10.0.
	if score > 10.0 {
		score = 10.0
	}

	detail := "all checks passed"
	if len(details) > 0 {
		detail = strings.Join(details, "; ")
	}

	signalScore := model.SignalScore{
		Name:   "publishing_hygiene",
		Score:  score,
		Detail: detail,
	}

	findings := buildHygieneFindings(score)

	return signalScore, findings
}

// buildHygieneFindings produces findings based on the computed hygiene score.
func buildHygieneFindings(score float64) []model.Finding {
	var findings []model.Finding

	switch {
	case score >= 8.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "publishing_hygiene",
			Message:  "Direct token publishing not restricted",
			Detail:   fmt.Sprintf("Publishing hygiene score %.1f/10.0 indicates no trusted publishing enforcement", score),
		})
	case score >= 5.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "publishing_hygiene",
			Message:  "Mixed publishing methods detected",
			Detail:   fmt.Sprintf("Publishing hygiene score %.1f/10.0 indicates inconsistent provenance practices", score),
		})
	case score >= 3.0:
		findings = append(findings, model.Finding{
			Severity: model.SeverityLow,
			Signal:   "publishing_hygiene",
			Message:  "Publishing hygiene could be improved",
			Detail:   fmt.Sprintf("Publishing hygiene score %.1f/10.0 suggests room for improvement", score),
		})
	default:
		findings = append(findings, model.Finding{
			Severity: model.SeverityInfo,
			Signal:   "publishing_hygiene",
			Message:  "Good publishing hygiene practices",
			Detail:   fmt.Sprintf("Publishing hygiene score %.1f/10.0 indicates strong practices", score),
		})
	}

	return findings
}

// isBotPublisher reports whether the given publisher name looks like a CI/CD
// bot rather than a human maintainer. Common bot indicators include names
// containing "bot", "ci", "automation", or "github-actions".
var botIndicators = []string{"bot", "ci", "automation", "github-actions"}

func isBotPublisher(name string) bool {
	lower := strings.ToLower(name)
	for _, indicator := range botIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}
