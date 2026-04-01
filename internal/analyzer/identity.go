// Package analyzer implements the security analysis signals for chainrecon.
package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chainrecon/chainrecon/internal/model"
)

// IdentityAnalyzer evaluates the stability of publisher identity across
// package versions. It detects maintainer email changes, new unknown
// publishers, and publishing cadence anomalies that may indicate account
// compromise or takeover. See Section 6.6 of the project definition.
type IdentityAnalyzer interface {
	// Analyze scores the identity stability signal and generates findings
	// for the given package metadata. The sortedVersions slice is ordered
	// newest-first (index 0 = latest version).
	Analyze(metadata *model.PackageMetadata, sortedVersions []string) (model.SignalScore, []model.Finding)
}

// identityAnalyzer is the default implementation of IdentityAnalyzer.
type identityAnalyzer struct{}

// NewIdentityAnalyzer returns a new IdentityAnalyzer ready for use.
func NewIdentityAnalyzer() IdentityAnalyzer {
	return &identityAnalyzer{}
}

// Scoring constants for identity signal checks.
const (
	identityScoreEmailChange      = 4.0 // email change between recent versions
	identityScoreNewPublisher     = 3.0 // unknown publisher on latest version
	identityScoreCadenceAnomaly   = 2.0 // publishing cadence anomaly on latest version
	identityScoreMultipleAuthors  = 1.0 // multiple different publishers across recent versions
	identityScoreMax              = 10.0
	identityVersionWindow         = 10  // number of recent versions to inspect
	cadenceAnomalyLowThreshold    = 0.25 // flag if latest gap < 25% of average
	cadenceAnomalyHighThreshold   = 3.00 // flag if latest gap > 300% of average
)

// Analyze inspects the publisher identity across recent versions to produce
// an identity-stability risk score from 0.0 (stable identity, consistent
// patterns) to 10.0 (recent email change, new accounts, anomalous publishing
// times). It checks for:
//   - Maintainer email changes across consecutive versions
//   - New/unknown publisher on the latest version
//   - Publishing cadence anomalies on the latest version
//   - Multiple different publishers across recent versions
//
// Account freshness is not directly available from registry metadata and is
// not scored; the remaining checks are used for the final score.
func (a *identityAnalyzer) Analyze(metadata *model.PackageMetadata, sortedVersions []string) (model.SignalScore, []model.Finding) {
	score := 0.0
	var findings []model.Finding
	var details []string

	// Limit to the most recent versions.
	versions := sortedVersions
	if len(versions) > identityVersionWindow {
		versions = versions[:identityVersionWindow]
	}

	// --- Check 1: Maintainer email changes across consecutive versions ---
	emailChanged, oldEmail, newEmail := a.detectEmailChange(metadata, versions)
	if emailChanged {
		score += identityScoreEmailChange
		details = append(details, fmt.Sprintf("email changed from %s to %s", oldEmail, newEmail))
		findings = append(findings, model.Finding{
			Severity: model.SeverityCritical,
			Signal:   "identity",
			Message:  "Maintainer email changed between versions",
			Detail:   fmt.Sprintf("Publisher email changed from %s to %s", oldEmail, newEmail),
		})
	}

	// --- Check 2: New/unknown publisher on latest version ---
	newPublisher, publisherName := a.detectNewPublisher(metadata, versions)
	if newPublisher {
		score += identityScoreNewPublisher
		details = append(details, fmt.Sprintf("unknown publisher %q on latest version", publisherName))
		findings = append(findings, model.Finding{
			Severity: model.SeverityHigh,
			Signal:   "identity",
			Message:  "Unknown publisher on recent version",
			Detail:   fmt.Sprintf("Publisher %q is not in the package maintainers list", publisherName),
		})
	}

	// --- Check 3: Publishing cadence anomaly ---
	cadenceAnomalous := a.detectCadenceAnomaly(metadata, versions)
	if cadenceAnomalous {
		score += identityScoreCadenceAnomaly
		details = append(details, "publishing cadence anomaly on latest version")
		findings = append(findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "identity",
			Message:  "Publishing cadence anomaly detected",
			Detail:   "The latest version was published significantly faster or slower than the historical average",
		})
	}

	// --- Check 4: Multiple different publishers across recent versions ---
	multiplePublishers := a.detectMultiplePublishers(metadata, versions)
	if multiplePublishers {
		score += identityScoreMultipleAuthors
		details = append(details, "multiple different publishers across recent versions")
		findings = append(findings, model.Finding{
			Severity: model.SeverityLow,
			Signal:   "identity",
			Message:  "Multiple different publishers across recent versions",
			Detail:   fmt.Sprintf("More than one publisher found in the last %d versions", len(versions)),
		})
	}

	// If no issues were found, emit an informational finding.
	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			Severity: model.SeverityInfo,
			Signal:   "identity",
			Message:  "No identity changes detected",
			Detail:   fmt.Sprintf("Checked %d versions; publisher identity is stable", len(versions)),
		})
	}

	// Cap at maximum score.
	if score > identityScoreMax {
		score = identityScoreMax
	}

	detail := "no identity issues detected"
	if len(details) > 0 {
		detail = strings.Join(details, "; ")
	}

	signalScore := model.SignalScore{
		Name:   "identity",
		Score:  score,
		Detail: detail,
	}

	return signalScore, findings
}

// detectEmailChange walks consecutive version pairs (newest to oldest) and
// returns true if the _npmUser email changed between any two adjacent
// versions. It returns the old and new email addresses for the first change
// found.
func (a *identityAnalyzer) detectEmailChange(metadata *model.PackageMetadata, versions []string) (changed bool, oldEmail, newEmail string) {
	for i := 0; i < len(versions)-1; i++ {
		newerVer := versions[i]
		olderVer := versions[i+1]

		newerDetail, newerOK := metadata.Versions[newerVer]
		olderDetail, olderOK := metadata.Versions[olderVer]

		if !newerOK || !olderOK {
			continue
		}
		if newerDetail.NPMUser == nil || olderDetail.NPMUser == nil {
			continue
		}

		newerEmail := strings.ToLower(newerDetail.NPMUser.Email)
		olderEmail := strings.ToLower(olderDetail.NPMUser.Email)

		if newerEmail != olderEmail && newerEmail != "" && olderEmail != "" {
			return true, olderEmail, newerEmail
		}
	}
	return false, "", ""
}

// detectNewPublisher checks whether the _npmUser on the latest version is a
// name not present in the package's Maintainers list. This catches the
// scenario where a new account publishes a version without being a recognized
// maintainer.
func (a *identityAnalyzer) detectNewPublisher(metadata *model.PackageMetadata, versions []string) (isNew bool, name string) {
	if len(versions) == 0 {
		return false, ""
	}

	latestVer := versions[0]
	vd, ok := metadata.Versions[latestVer]
	if !ok || vd.NPMUser == nil {
		return false, ""
	}

	publisherName := strings.ToLower(vd.NPMUser.Name)
	if publisherName == "" {
		return false, ""
	}

	// Build a set of known maintainer names.
	maintainerNames := make(map[string]bool, len(metadata.Maintainers))
	for _, m := range metadata.Maintainers {
		maintainerNames[strings.ToLower(m.Name)] = true
	}

	if !maintainerNames[publisherName] {
		return true, vd.NPMUser.Name
	}

	return false, ""
}

// detectCadenceAnomaly checks whether the time gap between the latest
// version and its predecessor is anomalous relative to the average publishing
// cadence. An anomaly is defined as a gap less than 25% or more than 300% of
// the average gap across the inspected versions.
func (a *identityAnalyzer) detectCadenceAnomaly(metadata *model.PackageMetadata, versions []string) bool {
	if len(versions) < 3 {
		// Need at least 3 versions to compute a meaningful average gap.
		return false
	}

	// Resolve publish times for each version, sorted newest-first.
	type versionTime struct {
		version string
		t       time.Time
	}
	var vts []versionTime
	for _, v := range versions {
		if t, ok := metadata.Time[v]; ok {
			vts = append(vts, versionTime{version: v, t: t})
		}
	}

	if len(vts) < 3 {
		return false
	}

	// Ensure the times are sorted newest-first (same order as versions).
	sort.Slice(vts, func(i, j int) bool {
		return vts[i].t.After(vts[j].t)
	})

	// Compute gaps between consecutive versions (newest to oldest).
	var gaps []time.Duration
	for i := 0; i < len(vts)-1; i++ {
		gap := vts[i].t.Sub(vts[i+1].t)
		if gap < 0 {
			gap = -gap
		}
		gaps = append(gaps, gap)
	}

	if len(gaps) < 2 {
		return false
	}

	// The latest gap is index 0 (between the two newest versions).
	latestGap := gaps[0]

	// Compute average of all other gaps (excluding the latest).
	var sumOther float64
	for _, g := range gaps[1:] {
		sumOther += float64(g)
	}
	avgOther := sumOther / float64(len(gaps)-1)

	if avgOther == 0 {
		return false
	}

	ratio := float64(latestGap) / avgOther

	return ratio < cadenceAnomalyLowThreshold || ratio > cadenceAnomalyHighThreshold
}

// detectMultiplePublishers checks whether more than one distinct _npmUser
// name published versions within the inspection window.
func (a *identityAnalyzer) detectMultiplePublishers(metadata *model.PackageMetadata, versions []string) bool {
	publishers := make(map[string]bool)

	for _, v := range versions {
		vd, ok := metadata.Versions[v]
		if !ok || vd.NPMUser == nil {
			continue
		}
		name := strings.ToLower(vd.NPMUser.Name)
		if name != "" {
			publishers[name] = true
		}
	}

	return len(publishers) > 1
}

