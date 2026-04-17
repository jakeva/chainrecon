package analyzer

import (
	"fmt"
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestMaintainerAnalyzer_SingleMaintainerPersonalEmail_Unscoped(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "vulnerable-pkg",
		Maintainers: []model.Maintainer{
			{Name: "solodev", Email: "solodev@gmail.com"},
		},
		Versions: map[string]model.VersionDetail{
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "solodev", Email: "solodev@gmail.com"},
			},
		},
	}

	signal, findings := ma.Analyze(metadata)

	// count: 4.0 (1 maintainer) + bus: 3.0 (100%) + email: 2.0 (personal) + scope: 1.0 (unscoped) = 10.0
	if signal.Score < 8.0 || signal.Score > 10.0 {
		t.Errorf("single maintainer personal email score = %.2f, want 8.0-10.0", signal.Score)
	}

	if signal.Name != "maintainer_risk" {
		t.Errorf("signal name = %q, want %q", signal.Name, "maintainer_risk")
	}

	// Verify CRITICAL finding for single maintainer.
	foundCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && f.Signal == "maintainer_risk" {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("expected CRITICAL finding for single maintainer, not found")
	}

	// Verify HIGH finding for personal email.
	foundHighEmail := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh && f.Signal == "maintainer_risk" {
			foundHighEmail = true
			break
		}
	}
	if !foundHighEmail {
		t.Error("expected HIGH finding for personal email, not found")
	}
}

func TestMaintainerAnalyzer_MultipleMaintainersOrgEmail_Scoped(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	maintainers := []model.Maintainer{
		{Name: "alice", Email: "alice@company.com"},
		{Name: "bob", Email: "bob@company.com"},
		{Name: "charlie", Email: "charlie@company.com"},
		{Name: "diana", Email: "diana@company.com"},
		{Name: "eve", Email: "eve@company.com"},
	}

	versions := map[string]model.VersionDetail{
		"5.0.0": {Version: "5.0.0", NPMUser: &model.NPMUser{Name: "alice", Email: "alice@company.com"}},
		"4.0.0": {Version: "4.0.0", NPMUser: &model.NPMUser{Name: "bob", Email: "bob@company.com"}},
		"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "charlie", Email: "charlie@company.com"}},
		"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "diana", Email: "diana@company.com"}},
		"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "eve", Email: "eve@company.com"}},
	}

	metadata := &model.PackageMetadata{
		Name:        "@myorg/secure-pkg",
		Maintainers: maintainers,
		Versions:    versions,
	}

	signal, findings := ma.Analyze(metadata)

	// count: 0.5 (5+ maintainers) + bus: 0.5 (each publishes 20%) + email: 0.0 (org) + scope: 0.0 (scoped) = 1.0
	if signal.Score < 1.0 || signal.Score > 2.0 {
		t.Errorf("5+ maintainers org email scoped score = %.2f, want 1.0-2.0", signal.Score)
	}

	// Should not have CRITICAL finding.
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			t.Errorf("unexpected CRITICAL finding for well-maintained package: %v", f)
		}
	}
}

func TestMaintainerAnalyzer_TwoMaintainers_BusFactor(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	// One publisher publishes 9 out of 10 versions (90%) -> bus factor > 80%.
	versions := make(map[string]model.VersionDetail)
	for i := 1; i <= 9; i++ {
		ver := "1.0." + string(rune('0'+i))
		versions[ver] = model.VersionDetail{
			Version: ver,
			NPMUser: &model.NPMUser{Name: "primarydev", Email: "primary@company.com"},
		}
	}
	versions["1.0.0"] = model.VersionDetail{
		Version: "1.0.0",
		NPMUser: &model.NPMUser{Name: "secondarydev", Email: "secondary@company.com"},
	}

	metadata := &model.PackageMetadata{
		Name: "bus-factor-pkg",
		Maintainers: []model.Maintainer{
			{Name: "primarydev", Email: "primary@company.com"},
			{Name: "secondarydev", Email: "secondary@company.com"},
		},
		Versions: versions,
	}

	signal, findings := ma.Analyze(metadata)

	// count: 2.5 (2 maintainers) + bus: 3.0 (90% > 80%) + email: 0.0 (org) + scope: 1.0 (unscoped) = 6.5.
	if signal.Score < 5.0 || signal.Score > 7.5 {
		t.Errorf("two maintainers bus factor score = %.2f, want ~5.0-7.5", signal.Score)
	}

	// Should have HIGH finding for >80% bus factor.
	foundBusFactor := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh && f.Signal == "maintainer_risk" {
			foundBusFactor = true
			break
		}
	}
	if !foundBusFactor {
		t.Error("expected HIGH finding for bus factor > 80%")
	}
}

func TestMaintainerAnalyzer_CRITICAL_FindingForSingleMaintainer(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "solo-pkg",
		Maintainers: []model.Maintainer{
			{Name: "lonedev", Email: "lone@company.com"},
		},
		Versions: map[string]model.VersionDetail{
			"1.0.0": {
				Version: "1.0.0",
				NPMUser: &model.NPMUser{Name: "lonedev", Email: "lone@company.com"},
			},
		},
	}

	_, findings := ma.Analyze(metadata)

	if len(findings) == 0 {
		t.Fatal("expected findings for single maintainer")
	}

	foundCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			foundCritical = true
			if f.Signal != "maintainer_risk" {
				t.Errorf("CRITICAL finding signal = %q, want %q", f.Signal, "maintainer_risk")
			}
		}
	}
	if !foundCritical {
		t.Error("expected CRITICAL finding for single maintainer, not found")
	}
}

func TestMaintainerAnalyzer_ScoreClampedBetween1And10(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	tests := []struct {
		name     string
		metadata *model.PackageMetadata
	}{
		{
			name: "minimum score floor at 1.0",
			metadata: &model.PackageMetadata{
				Name: "@org/safe-pkg",
				Maintainers: []model.Maintainer{
					{Name: "a", Email: "a@co.com"},
					{Name: "b", Email: "b@co.com"},
					{Name: "c", Email: "c@co.com"},
					{Name: "d", Email: "d@co.com"},
					{Name: "e", Email: "e@co.com"},
					{Name: "f", Email: "f@co.com"},
				},
				Versions: map[string]model.VersionDetail{
					"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "a", Email: "a@co.com"}},
					"2.0.0": {Version: "2.0.0", NPMUser: &model.NPMUser{Name: "b", Email: "b@co.com"}},
					"3.0.0": {Version: "3.0.0", NPMUser: &model.NPMUser{Name: "c", Email: "c@co.com"}},
				},
			},
		},
		{
			name: "maximum score ceiling at 10.0",
			metadata: &model.PackageMetadata{
				Name: "risky-pkg",
				Maintainers: []model.Maintainer{
					{Name: "solo", Email: "solo@gmail.com"},
				},
				Versions: map[string]model.VersionDetail{
					"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "solo", Email: "solo@gmail.com"}},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, _ := ma.Analyze(tc.metadata)
			if signal.Score < 1.0 {
				t.Errorf("score = %.2f, must be >= 1.0", signal.Score)
			}
			if signal.Score > 10.0 {
				t.Errorf("score = %.2f, must be <= 10.0", signal.Score)
			}
		})
	}
}

func TestMaintainerAnalyzer_UnscopedPackageFinding(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	metadata := &model.PackageMetadata{
		Name: "unscoped-limited",
		Maintainers: []model.Maintainer{
			{Name: "dev1", Email: "dev1@org.com"},
			{Name: "dev2", Email: "dev2@org.com"},
		},
		Versions: map[string]model.VersionDetail{
			"1.0.0": {Version: "1.0.0", NPMUser: &model.NPMUser{Name: "dev1", Email: "dev1@org.com"}},
		},
	}

	_, findings := ma.Analyze(metadata)

	// Unscoped + <= 2 maintainers -> MEDIUM finding.
	foundMedium := false
	for _, f := range findings {
		if f.Severity == model.SeverityMedium && f.Signal == "maintainer_risk" {
			foundMedium = true
			break
		}
	}
	if !foundMedium {
		t.Error("expected MEDIUM finding for unscoped package with limited maintainers")
	}
}

func TestMaintainerAnalyzer_BusFactor_VersionsWithoutNPMUser(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	// 10 versions total, but only 4 have NPMUser set. One publisher owns all 4.
	// Old behavior: 4/4 = 100% -> bus score 3.0
	// Fixed behavior: 4/10 = 40% -> bus score 0.5
	versions := make(map[string]model.VersionDetail)
	for i := 0; i < 4; i++ {
		ver := fmt.Sprintf("2.0.%d", i)
		versions[ver] = model.VersionDetail{
			Version: ver,
			NPMUser: &model.NPMUser{Name: "maindev", Email: "dev@company.com"},
		}
	}
	for i := 0; i < 6; i++ {
		ver := fmt.Sprintf("1.0.%d", i)
		versions[ver] = model.VersionDetail{Version: ver}
	}

	metadata := &model.PackageMetadata{
		Name: "@org/mixed-pkg",
		Maintainers: []model.Maintainer{
			{Name: "maindev", Email: "dev@company.com"},
			{Name: "other", Email: "other@company.com"},
			{Name: "third", Email: "third@company.com"},
		},
		Versions: versions,
	}

	_, findings := ma.Analyze(metadata)

	// 40% concentration should NOT trigger the >80% finding.
	for _, f := range findings {
		if f.Severity == model.SeverityHigh && f.Message == "Single publisher responsible for >80% of versions" {
			t.Errorf("should not flag >80%% bus factor when real concentration is 40%%: %v", f)
		}
	}
}

func TestMaintainerAnalyzer_EmptyMaintainers(t *testing.T) {
	ma := NewMaintainerAnalyzer()

	metadata := &model.PackageMetadata{
		Name:        "no-maintainers",
		Maintainers: nil,
		Versions:    map[string]model.VersionDetail{},
	}

	signal, _ := ma.Analyze(metadata)

	// 0 maintainers -> countScore 4.0, so score should be at least 1.0 (floor).
	if signal.Score < 1.0 {
		t.Errorf("score = %.2f, must be >= 1.0", signal.Score)
	}
}
