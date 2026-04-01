// Package analyzer implements signal analysis for chainrecon.
package analyzer

import (
	"fmt"

	"github.com/chainrecon/chainrecon/internal/model"
)

// ProvenanceAnalyzer evaluates provenance attestation history for a package
// and produces a risk score with findings.
type ProvenanceAnalyzer interface {
	// Analyze scores the provenance signal based on the attestation history.
	// The attestations slice is ordered newest-first (index 0 = latest version).
	Analyze(attestations []model.VersionAttestation) (model.SignalScore, []model.Finding)

	// ClassifyState determines the provenance state machine classification
	// for the given attestation history.
	ClassifyState(attestations []model.VersionAttestation) model.ProvenanceState
}

// provenanceAnalyzer is the default implementation of ProvenanceAnalyzer.
type provenanceAnalyzer struct{}

// NewProvenanceAnalyzer returns a new ProvenanceAnalyzer.
func NewProvenanceAnalyzer() ProvenanceAnalyzer {
	return &provenanceAnalyzer{}
}

// Base scores for each provenance state (Section 6.1).
const (
	baseScoreNever        = 5.0
	baseScoreActive       = 1.0
	baseScoreDropped      = 9.0
	baseScoreIntermittent = 6.0
	maxScore              = 10.0
	modifierLatestDropped = 1.0
	modifierPerGap        = 0.5
	recentWindow          = 3  // latest + next 2 versions for ACTIVE check
	gapScanWindow         = 10 // scan the last 10 versions for gap modifiers
)

// Analyze scores the provenance signal and generates findings.
// The attestations slice must be ordered newest-first.
func (p *provenanceAnalyzer) Analyze(attestations []model.VersionAttestation) (model.SignalScore, []model.Finding) {
	state := p.ClassifyState(attestations)
	score := p.baseScore(state)
	score = p.applyModifiers(score, attestations)

	detail := fmt.Sprintf("state=%s versions_checked=%d", string(state), len(attestations))
	signal := model.SignalScore{
		Name:   "provenance",
		Score:  score,
		Detail: detail,
	}

	findings := p.generateFindings(state, attestations)
	return signal, findings
}

// ClassifyState implements the provenance state machine (Section 3.3).
// The attestations slice is ordered newest-first (index 0 = latest version).
func (p *provenanceAnalyzer) ClassifyState(attestations []model.VersionAttestation) model.ProvenanceState {
	if len(attestations) == 0 {
		return model.ProvenanceNever
	}

	anyProvenance := false
	allProvenance := true
	for _, a := range attestations {
		if a.HasAnyProvenance {
			anyProvenance = true
		} else {
			allProvenance = false
		}
	}

	// NEVER: no version has any provenance.
	if !anyProvenance {
		return model.ProvenanceNever
	}

	latest := attestations[0]

	// DROPPED: at least one older version has provenance but the latest does not.
	if !latest.HasAnyProvenance {
		return model.ProvenanceDropped
	}

	// ACTIVE: the latest version and all recent versions have provenance.
	// "Recent" = latest plus at least the next 2, or all versions if fewer than 3.
	if allProvenance {
		return model.ProvenanceActive
	}

	recentEnd := recentWindow
	if recentEnd > len(attestations) {
		recentEnd = len(attestations)
	}
	recentAllHave := true
	for i := 0; i < recentEnd; i++ {
		if !attestations[i].HasAnyProvenance {
			recentAllHave = false
			break
		}
	}

	// If the recent window is all provenance, check whether the older versions
	// form a consistent gap pattern. When there are only old gaps but the
	// recent run is solid, classify as ACTIVE.
	if recentAllHave {
		// Further examine: if every version before the recent window lacks
		// provenance, that is still ACTIVE (provenance was adopted recently).
		// If there are mixed older versions (some have, some don't), it's
		// INTERMITTENT because provenance appeared and disappeared.
		olderAllMissing := true
		olderAnyHave := false
		olderAnyMissing := false
		for i := recentEnd; i < len(attestations); i++ {
			if attestations[i].HasAnyProvenance {
				olderAllMissing = false
				olderAnyHave = true
			} else {
				olderAnyMissing = false
				_ = olderAnyMissing // avoid unused warning
				olderAnyMissing = true
			}
		}

		// If all older versions lack provenance, the package recently adopted
		// provenance consistently -> ACTIVE.
		if olderAllMissing || !olderAnyHave {
			return model.ProvenanceActive
		}

		// Older versions have a mix (some with, some without) but the recent
		// window is clean -> INTERMITTENT (provenance appeared and disappeared).
		return model.ProvenanceIntermittent
	}

	// Latest has provenance but the recent window has gaps -> INTERMITTENT.
	return model.ProvenanceIntermittent
}

// baseScore returns the starting score for the given state.
func (p *provenanceAnalyzer) baseScore(state model.ProvenanceState) float64 {
	switch state {
	case model.ProvenanceNever:
		return baseScoreNever
	case model.ProvenanceActive:
		return baseScoreActive
	case model.ProvenanceDropped:
		return baseScoreDropped
	case model.ProvenanceIntermittent:
		return baseScoreIntermittent
	default:
		return baseScoreNever
	}
}

// applyModifiers adjusts the base score using version-level signals.
func (p *provenanceAnalyzer) applyModifiers(score float64, attestations []model.VersionAttestation) float64 {
	if len(attestations) == 0 {
		return score
	}

	// +1.0 if the latest version lacks provenance while a previous version had it.
	latest := attestations[0]
	if !latest.HasAnyProvenance {
		for _, a := range attestations[1:] {
			if a.HasAnyProvenance {
				score += modifierLatestDropped
				break
			}
		}
	}

	// +0.5 per gap in the last 10 versions.
	// A "gap" is a version without provenance where at least one neighbor has provenance.
	scanEnd := gapScanWindow
	if scanEnd > len(attestations) {
		scanEnd = len(attestations)
	}
	window := attestations[:scanEnd]
	for i, a := range window {
		if a.HasAnyProvenance {
			continue
		}
		hasProvenanceNeighbor := false
		if i > 0 && window[i-1].HasAnyProvenance {
			hasProvenanceNeighbor = true
		}
		if i < len(window)-1 && window[i+1].HasAnyProvenance {
			hasProvenanceNeighbor = true
		}
		if hasProvenanceNeighbor {
			score += modifierPerGap
		}
	}

	if score > maxScore {
		score = maxScore
	}
	return score
}

// generateFindings produces the appropriate findings for the given state.
func (p *provenanceAnalyzer) generateFindings(state model.ProvenanceState, attestations []model.VersionAttestation) []model.Finding {
	var findings []model.Finding

	switch state {
	case model.ProvenanceDropped:
		findings = append(findings, model.Finding{
			Severity: model.SeverityCritical,
			Signal:   "provenance",
			Message:  "Provenance dropped on latest version",
			Detail:   fmt.Sprintf("Latest version %s lacks provenance", p.latestVersion(attestations)),
		})

	case model.ProvenanceIntermittent:
		gaps, withProv, total := p.gapStats(attestations)
		pct := 0.0
		if total > 0 {
			pct = float64(withProv) / float64(total) * 100
		}
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "provenance",
			Message:  "Provenance is intermittent across versions",
			Detail:   fmt.Sprintf("%d gaps found, %.0f%% of versions have provenance (%d/%d)", gaps, pct, withProv, total),
		})

	case model.ProvenanceNever:
		findings = append(findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "provenance",
			Message:  "Package has never published with provenance",
			Detail:   fmt.Sprintf("Checked %d versions, none have provenance", len(attestations)),
		})

	case model.ProvenanceActive:
		findings = append(findings, model.Finding{
			Severity: model.SeverityInfo,
			Signal:   "provenance",
			Message:  "Provenance active across recent versions",
			Detail:   fmt.Sprintf("Checked %d versions", len(attestations)),
		})
	}

	return findings
}

// latestVersion returns the version string for the latest attestation, or
// "unknown" if the slice is empty.
func (p *provenanceAnalyzer) latestVersion(attestations []model.VersionAttestation) string {
	if len(attestations) == 0 {
		return "unknown"
	}
	return attestations[0].Version
}

// gapStats computes the number of provenance gaps, the count of versions with
// provenance, and the total number of versions.
func (p *provenanceAnalyzer) gapStats(attestations []model.VersionAttestation) (gaps, withProvenance, total int) {
	total = len(attestations)
	for i, a := range attestations {
		if a.HasAnyProvenance {
			withProvenance++
			continue
		}
		// A gap is a version without provenance that has at least one
		// neighboring version with provenance.
		hasNeighbor := false
		if i > 0 && attestations[i-1].HasAnyProvenance {
			hasNeighbor = true
		}
		if i < len(attestations)-1 && attestations[i+1].HasAnyProvenance {
			hasNeighbor = true
		}
		if hasNeighbor {
			gaps++
		}
	}
	return gaps, withProvenance, total
}
