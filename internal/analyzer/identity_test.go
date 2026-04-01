package analyzer

import (
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestIdentityAnalyzer_StableIdentity(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "stable-pkg",
		Versions: map[string]model.VersionDetail{
			"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
		},
		Time: map[string]time.Time{
			"3.0.0": time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			"2.0.0": time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"3.0.0", "2.0.0", "1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	if signal.Name != "identity" {
		t.Errorf("signal name = %q, want %q", signal.Name, "identity")
	}

	// Stable identity: same publisher, consistent cadence, known maintainer -> score 0.0.
	if signal.Score > 0.1 {
		t.Errorf("stable identity score = %.2f, want ~0.0", signal.Score)
	}

	// Should have an INFO finding.
	foundInfo := false
	for _, f := range findings {
		if f.Severity == model.SeverityInfo {
			foundInfo = true
			break
		}
	}
	if !foundInfo {
		t.Error("expected INFO finding for stable identity")
	}
}

func TestIdentityAnalyzer_EmailChange(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "email-change-pkg",
		Versions: map[string]model.VersionDetail{
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@newdomain.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@olddomain.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@newdomain.com"},
		},
		Time: map[string]time.Time{
			"2.0.0": time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"2.0.0", "1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	// Email change contributes +4.0.
	if signal.Score < 3.9 {
		t.Errorf("email change score = %.2f, want >= 4.0", signal.Score)
	}

	// Should have CRITICAL finding for email change.
	foundCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && f.Signal == "identity" {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("expected CRITICAL finding for email change between versions")
	}
}

func TestIdentityAnalyzer_UnknownPublisher(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "unknown-pub-pkg",
		Versions: map[string]model.VersionDetail{
			"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "stranger", Email: "stranger@evil.com"}},
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
			{Name: "bob", Email: "bob@company.com"},
		},
		Time: map[string]time.Time{
			"3.0.0": time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			"2.0.0": time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"3.0.0", "2.0.0", "1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	// Unknown publisher: +3.0. Also email changed (stranger vs alice): +4.0.
	// Multiple publishers: +1.0.
	if signal.Score < 3.0 {
		t.Errorf("unknown publisher score = %.2f, want >= 3.0", signal.Score)
	}

	// Should have HIGH finding for unknown publisher.
	foundHigh := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh && f.Signal == "identity" {
			foundHigh = true
			break
		}
	}
	if !foundHigh {
		t.Error("expected HIGH finding for unknown publisher on latest version")
	}
}

func TestIdentityAnalyzer_MultiplePublishers(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "multi-pub-pkg",
		Versions: map[string]model.VersionDetail{
			"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "bob", Email: "bob@company.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
			{Name: "bob", Email: "bob@company.com"},
		},
		Time: map[string]time.Time{
			"3.0.0": time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			"2.0.0": time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"3.0.0", "2.0.0", "1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	// Multiple publishers: +1.0. Email change (alice vs bob different emails): +4.0.
	// Both are known maintainers so no unknown publisher penalty.
	if signal.Score < 1.0 {
		t.Errorf("multiple publishers score = %.2f, want >= 1.0", signal.Score)
	}

	// Should have LOW finding for multiple publishers.
	foundLow := false
	for _, f := range findings {
		if f.Severity == model.SeverityLow && f.Signal == "identity" {
			foundLow = true
			break
		}
	}
	if !foundLow {
		t.Error("expected LOW finding for multiple different publishers")
	}
}

func TestIdentityAnalyzer_CadenceAnomaly(t *testing.T) {
	ia := NewIdentityAnalyzer()

	// Versions published roughly monthly, but the latest is published
	// the day after the previous one (anomalously fast: ratio < 0.25).
	metadata := &model.PackageMetadata{
		Name: "cadence-pkg",
		Versions: map[string]model.VersionDetail{
			"4.0.0": {Version: "4.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@co.com"}},
			"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@co.com"}},
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@co.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@co.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@co.com"},
		},
		Time: map[string]time.Time{
			"4.0.0": time.Date(2025, 4, 2, 0, 0, 0, 0, time.UTC),  // 1 day after 3.0.0
			"3.0.0": time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
			"2.0.0": time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"4.0.0", "3.0.0", "2.0.0", "1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	// Cadence anomaly: +2.0.
	if signal.Score < 1.9 {
		t.Errorf("cadence anomaly score = %.2f, want >= 2.0", signal.Score)
	}

	// Should have MEDIUM finding for cadence anomaly.
	foundMedium := false
	for _, f := range findings {
		if f.Severity == model.SeverityMedium && f.Signal == "identity" {
			foundMedium = true
			break
		}
	}
	if !foundMedium {
		t.Error("expected MEDIUM finding for publishing cadence anomaly")
	}
}

func TestIdentityAnalyzer_EmptyVersions(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name:        "empty-pkg",
		Versions:    map[string]model.VersionDetail{},
		Maintainers: nil,
		Time:        map[string]time.Time{},
	}

	signal, findings := ia.Analyze(metadata, nil)

	if signal.Name != "identity" {
		t.Errorf("signal name = %q, want %q", signal.Name, "identity")
	}

	if signal.Score != 0.0 {
		t.Errorf("empty versions score = %.2f, want 0.0", signal.Score)
	}

	// Should get an INFO finding for no identity issues.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityInfo)
	}
}

func TestIdentityAnalyzer_ScoreCappedAt10(t *testing.T) {
	ia := NewIdentityAnalyzer()

	// Trigger all checks to maximize score:
	// email change (+4.0), unknown publisher (+3.0), cadence anomaly (+2.0),
	// multiple publishers (+1.0) = 10.0.
	metadata := &model.PackageMetadata{
		Name: "max-risk-pkg",
		Versions: map[string]model.VersionDetail{
			"4.0.0": {Version: "4.0.0", NPMUser: &model.NPMUser{Name: "stranger", Email: "evil@bad.com"}},
			"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
		},
		Time: map[string]time.Time{
			"4.0.0": time.Date(2025, 4, 2, 0, 0, 0, 0, time.UTC),  // 1 day after (cadence anomaly)
			"3.0.0": time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
			"2.0.0": time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			"1.0.0": time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"4.0.0", "3.0.0", "2.0.0", "1.0.0"}

	signal, _ := ia.Analyze(metadata, sortedVersions)

	if signal.Score > 10.0 {
		t.Errorf("score = %.2f, must not exceed 10.0", signal.Score)
	}

	if signal.Score < 9.9 {
		t.Errorf("all checks triggered score = %.2f, want ~10.0", signal.Score)
	}
}

func TestIdentityAnalyzer_SingleVersion(t *testing.T) {
	ia := NewIdentityAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "single-ver-pkg",
		Versions: map[string]model.VersionDetail{
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
		},
		Time: map[string]time.Time{
			"1.0.0": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sortedVersions := []string{"1.0.0"}

	signal, findings := ia.Analyze(metadata, sortedVersions)

	// Single version: no email change, no multiple publishers, no cadence anomaly.
	// Publisher "alice" is in maintainers, so no unknown publisher.
	if signal.Score != 0.0 {
		t.Errorf("single version stable identity score = %.2f, want 0.0", signal.Score)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityInfo)
	}
}
