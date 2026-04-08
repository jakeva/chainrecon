package analyzer

import (
	"fmt"

	"github.com/chainrecon/chainrecon/internal/model"
)

// LifecycleAnalyzer detects newly added or modified lifecycle scripts in
// package.json. Lifecycle hooks like preinstall and postinstall run
// automatically during npm install and are a common vector for supply chain
// attacks.
type LifecycleAnalyzer interface {
	// Analyze inspects the old and new package.json scripts to detect
	// lifecycle hook additions and modifications.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// lifecycleAnalyzer is the default implementation of LifecycleAnalyzer.
type lifecycleAnalyzer struct{}

// NewLifecycleAnalyzer returns a new LifecycleAnalyzer.
func NewLifecycleAnalyzer() LifecycleAnalyzer {
	return &lifecycleAnalyzer{}
}

// criticalHooks are the hooks that auto-execute on install or uninstall and
// carry the highest risk when newly introduced.
var criticalHooks = map[string]bool{
	"preinstall":  true,
	"postinstall": true,
}

// allLifecycleHooks is the full list of hooks we check.
var allLifecycleHooks = []string{
	"preinstall", "install", "postinstall",
	"preuninstall", "uninstall", "postuninstall",
	"prepare",
}

// Analyze compares the scripts sections of old and new package.json files,
// looking for newly added or changed lifecycle hooks.
func (l *lifecycleAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	oldScripts := extractScripts(diff.OldPackageJSON)
	newScripts := extractScripts(diff.NewPackageJSON)

	var findings []model.CodeFinding

	for _, hook := range allLifecycleHooks {
		oldVal, oldExists := oldScripts[hook]
		newVal, newExists := newScripts[hook]

		if !newExists {
			continue
		}

		if !oldExists {
			// Hook was newly added.
			sev := model.SeverityMedium
			if criticalHooks[hook] {
				sev = model.SeverityCritical
			}
			findings = append(findings, model.CodeFinding{
				Severity: sev,
				Signal:   "lifecycle_script",
				Message:  fmt.Sprintf("New %q lifecycle script added", hook),
				Detail:   fmt.Sprintf("script: %s", newVal),
				File:     "package.json",
			})
			continue
		}

		if oldVal != newVal {
			// Hook existed before but its content changed.
			sev := model.SeverityHigh
			if !criticalHooks[hook] {
				sev = model.SeverityMedium
			}
			findings = append(findings, model.CodeFinding{
				Severity: sev,
				Signal:   "lifecycle_script",
				Message:  fmt.Sprintf("Lifecycle script %q was modified", hook),
				Detail:   fmt.Sprintf("old: %s | new: %s", oldVal, newVal),
				File:     "package.json",
			})
		}
	}

	return findings
}

// extractScripts pulls the "scripts" map out of a package.json represented
// as map[string]any. Returns an empty map if the key is missing or not the
// expected shape.
func extractScripts(pkg map[string]any) map[string]string {
	result := make(map[string]string)
	if pkg == nil {
		return result
	}
	raw, ok := pkg["scripts"]
	if !ok {
		return result
	}
	scripts, ok := raw.(map[string]any)
	if !ok {
		return result
	}
	for k, v := range scripts {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}
