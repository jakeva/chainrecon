package analyzer

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestHygieneAnalyzer_AllTrustedPublishing(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "@myorg/mypackage",
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]model.VersionDetail{
			"2.0.0": {
				Version: "2.0.0",
				NPMUser: &model.NPMUser{Name: "github-actions-bot", Email: "bot@github.com"},
			},
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "ci-automation", Email: "ci@org.com"},
			},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
			{Name: "bob", Email: "bob@company.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "2.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
		{Version: "1.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
	}

	signal, findings := ha.Analyze(metadata, attestations)

	if signal.Name != "publishing_hygiene" {
		t.Errorf("signal name = %q, want %q", signal.Name, "publishing_hygiene")
	}

	// All trusted, bot publisher, multiple maintainers -> should be near 0.
	if signal.Score > 2.0 {
		t.Errorf("fully trusted publishing score = %.2f, want <= 2.0", signal.Score)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Low score should produce an INFO finding.
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityInfo)
	}
}

func TestHygieneAnalyzer_NoProvenance_HumanPublisher_SingleMaintainer(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "my-package",
		DistTags: map[string]string{"latest": "1.0.0"},
		Versions: map[string]model.VersionDetail{
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "human@gmail.com"},
			},
		},
		Maintainers: []model.Maintainer{
			{Name: "humandev", Email: "human@gmail.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "1.0.0", HasSLSA: false, HasPublish: false, HasAnyProvenance: false},
	}

	signal, findings := ha.Analyze(metadata, attestations)

	// No provenance (+5.0), human publisher (+2.0), single maintainer (+1.0) = 8.0.
	if signal.Score < 7.9 || signal.Score > 8.1 {
		t.Errorf("no provenance + human + single maintainer score = %.2f, want ~8.0", signal.Score)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Score >= 8.0 should produce a HIGH finding.
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityHigh)
	}
}

func TestHygieneAnalyzer_MixedProvenance(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "@scope/mixed-pkg",
		DistTags: map[string]string{"latest": "3.0.0"},
		Versions: map[string]model.VersionDetail{
			"3.0.0": {
				Version: "3.0.0",
				NPMUser: &model.NPMUser{Name: "ci-bot", Email: "ci@org.com"},
			},
			"2.0.0": {
				Version: "2.0.0",
				NPMUser: &model.NPMUser{Name: "ci-bot", Email: "ci@org.com"},
			},
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "ci-bot", Email: "ci@org.com"},
			},
		},
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@company.com"},
			{Name: "bob", Email: "bob@company.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "3.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
		{Version: "2.0.0", HasSLSA: false, HasPublish: false, HasAnyProvenance: false},
		{Version: "1.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
	}

	signal, _ := ha.Analyze(metadata, attestations)

	// Mixed provenance (+2.0), bot publisher (+0), multiple maintainers (+0) = ~2.0.
	if signal.Score < 1.9 || signal.Score > 2.1 {
		t.Errorf("mixed provenance score = %.2f, want ~2.0", signal.Score)
	}
}

func TestHygieneAnalyzer_LatestDropsProvenance(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "dropped-prov-pkg",
		DistTags: map[string]string{"latest": "3.0.0"},
		Versions: map[string]model.VersionDetail{
			"3.0.0": {
				Version: "3.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "dev@example.com"},
			},
			"2.0.0": {
				Version: "2.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "dev@example.com"},
			},
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "dev@example.com"},
			},
		},
		Maintainers: []model.Maintainer{
			{Name: "humandev", Email: "dev@example.com"},
			{Name: "other", Email: "other@example.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "3.0.0", HasSLSA: false, HasPublish: false, HasAnyProvenance: false},
		{Version: "2.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
		{Version: "1.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
	}

	signal, findings := ha.Analyze(metadata, attestations)

	// Latest drops provenance (+3.0), human publisher (+2.0), mixed publishing (+2.0) = 7.0.
	if signal.Score < 6.9 || signal.Score > 7.1 {
		t.Errorf("latest drops provenance score = %.2f, want ~7.0", signal.Score)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Score >= 5.0 and < 8.0 -> MEDIUM finding.
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityMedium)
	}
}

func TestHygieneAnalyzer_ScoreCappedAt10(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "max-risk-pkg",
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]model.VersionDetail{
			"2.0.0": {
				Version: "2.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "dev@gmail.com"},
			},
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "humandev", Email: "dev@gmail.com"},
			},
		},
		Maintainers: []model.Maintainer{
			{Name: "humandev", Email: "dev@gmail.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "2.0.0", HasSLSA: false, HasPublish: false, HasAnyProvenance: false},
		{Version: "1.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
	}

	signal, _ := ha.Analyze(metadata, attestations)

	if signal.Score > 10.0 {
		t.Errorf("score = %.2f, must not exceed 10.0", signal.Score)
	}
}

func TestHygieneAnalyzer_NilMetadataDistTags(t *testing.T) {
	ha := NewHygieneAnalyzer()

	metadata := &model.PackageMetadata{
		Name:     "no-dist-tags",
		DistTags: nil,
		Versions: map[string]model.VersionDetail{},
		Maintainers: []model.Maintainer{
			{Name: "dev", Email: "dev@org.com"},
			{Name: "dev2", Email: "dev2@org.com"},
		},
	}

	attestations := []model.VersionAttestation{
		{Version: "1.0.0", HasSLSA: true, HasPublish: true, HasAnyProvenance: true},
	}

	signal, _ := ha.Analyze(metadata, attestations)

	// No dist-tags means checks relying on latest version are skipped.
	// All versions have provenance, so no +5.0 penalty.
	if signal.Score < 0.0 {
		t.Errorf("score = %.2f, should be >= 0.0", signal.Score)
	}
}
