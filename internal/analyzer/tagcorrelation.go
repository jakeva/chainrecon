package analyzer

import (
	"fmt"
	"slices"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// TagCorrelationAnalyzer detects npm versions that were published without
// a corresponding GitHub release or tag. This is a strong anomaly signal:
// the Axios attack published malicious versions that had no GitHub release.
type TagCorrelationAnalyzer interface {
	// Analyze compares npm versions against GitHub releases and returns
	// findings for any versions that lack a corresponding release.
	Analyze(versions []string, releases []model.GitHubRelease) []model.Finding
}

type tagCorrelationAnalyzer struct{}

// NewTagCorrelationAnalyzer returns a new TagCorrelationAnalyzer.
func NewTagCorrelationAnalyzer() TagCorrelationAnalyzer {
	return &tagCorrelationAnalyzer{}
}

// Analyze checks each npm version against the set of GitHub release tags.
// Tags are normalized: a leading "v" is stripped for comparison (v1.0.0 matches 1.0.0).
func (t *tagCorrelationAnalyzer) Analyze(versions []string, releases []model.GitHubRelease) []model.Finding {
	if len(releases) == 0 {
		return nil
	}

	// Build a set of known release tags (normalized).
	tagSet := make(map[string]bool, len(releases))
	for _, r := range releases {
		tag := normalizeTag(r.TagName)
		tagSet[tag] = true
	}

	var unmatched []string
	for _, v := range versions {
		nv := normalizeTag(v)
		if !tagSet[nv] {
			unmatched = append(unmatched, v)
		}
	}

	if len(unmatched) == 0 {
		return nil
	}

	var findings []model.Finding

	// Flag the first few unmatched versions.
	limit := 5
	if len(unmatched) < limit {
		limit = len(unmatched)
	}
	shown := unmatched[:limit]

	severity := model.SeverityMedium
	if len(unmatched) <= 2 {
		// Only 1-2 missing could be pre-release or minor, not necessarily suspicious.
		severity = model.SeverityLow
	}
	// If the most recent version (first in the sorted list) has no tag, that's more concerning.
	if len(versions) > 0 && slices.Contains(unmatched, versions[0]) {
		severity = model.SeverityHigh
	}

	msg := fmt.Sprintf("%d npm version(s) have no corresponding GitHub release", len(unmatched))
	detail := "Versions without releases: " + strings.Join(shown, ", ")
	if len(unmatched) > limit {
		detail += fmt.Sprintf(" (and %d more)", len(unmatched)-limit)
	}

	findings = append(findings, model.Finding{
		Severity: severity,
		Signal:   "tag_correlation",
		Message:  msg,
		Detail:   detail,
	})

	return findings
}

// normalizeTag strips a leading "v" from a tag name for comparison.
func normalizeTag(tag string) string {
	return strings.TrimPrefix(tag, "v")
}

