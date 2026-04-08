package analyzer

import (
	"fmt"

	"github.com/chainrecon/chainrecon/internal/model"
)

// DepInjectionAnalyzer detects new dependencies added between two versions
// of a package. New runtime dependencies are higher risk than dev or peer
// dependencies because they execute in production environments.
type DepInjectionAnalyzer interface {
	// Analyze compares dependency maps between old and new package.json to
	// find newly added dependencies.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// depInjectionAnalyzer is the default implementation of DepInjectionAnalyzer.
type depInjectionAnalyzer struct{}

// NewDepInjectionAnalyzer returns a new DepInjectionAnalyzer.
func NewDepInjectionAnalyzer() DepInjectionAnalyzer {
	return &depInjectionAnalyzer{}
}

// depCategory defines a dependency category with its package.json key name
// and the severity assigned when a new dependency appears in that category.
type depCategory struct {
	key      string
	label    string
	severity model.Severity
}

// depCategories lists the dependency categories we check, ordered from
// highest to lowest severity.
var depCategories = []depCategory{
	{key: "dependencies", label: "runtime", severity: model.SeverityHigh},
	{key: "optionalDependencies", label: "optional", severity: model.SeverityMedium},
	{key: "devDependencies", label: "dev", severity: model.SeverityLow},
	{key: "peerDependencies", label: "peer", severity: model.SeverityLow},
}

// Analyze walks each dependency category and reports any dependency that
// exists in the new package.json but not in the old one.
func (d *depInjectionAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	var findings []model.CodeFinding

	for _, cat := range depCategories {
		oldDeps := extractDeps(diff.OldPackageJSON, cat.key)
		newDeps := extractDeps(diff.NewPackageJSON, cat.key)

		for name, version := range newDeps {
			if _, existed := oldDeps[name]; existed {
				continue
			}
			findings = append(findings, model.CodeFinding{
				Severity: cat.severity,
				Signal:   "dependency_injection",
				Message:  fmt.Sprintf("New %s dependency %q added", cat.label, name),
				Detail:   fmt.Sprintf("version: %s", version),
				File:     "package.json",
			})
		}
	}

	return findings
}

// extractDeps pulls a dependency map (e.g. "dependencies", "devDependencies")
// from a package.json structure. Returns an empty map when the key is missing
// or has an unexpected type.
func extractDeps(pkg map[string]any, key string) map[string]string {
	result := make(map[string]string)
	if pkg == nil {
		return result
	}
	raw, ok := pkg[key]
	if !ok {
		return result
	}
	deps, ok := raw.(map[string]any)
	if !ok {
		return result
	}
	for name, v := range deps {
		if s, ok := v.(string); ok {
			result[name] = s
		}
	}
	return result
}
