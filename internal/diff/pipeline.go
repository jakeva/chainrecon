package diff

import (
	"github.com/chainrecon/chainrecon/internal/analyzer"
	"github.com/chainrecon/chainrecon/internal/model"
)

// Analysis holds the results of running all code analyzers on a release diff.
type Analysis struct {
	Diff     *model.ReleaseDiff  `json:"diff"`
	Findings []model.CodeFinding `json:"findings"`
}

// Analyze runs all code analyzers on the given release diff and returns
// the aggregated findings sorted by severity.
func Analyze(d *model.ReleaseDiff) *Analysis {
	var findings []model.CodeFinding

	findings = append(findings, analyzer.NewLifecycleAnalyzer().Analyze(d)...)
	findings = append(findings, analyzer.NewDepInjectionAnalyzer().Analyze(d)...)
	findings = append(findings, analyzer.NewObfuscationAnalyzer().Analyze(d)...)
	findings = append(findings, analyzer.NewNetworkAnalyzer().Analyze(d)...)
	findings = append(findings, analyzer.NewCredentialAnalyzer().Analyze(d)...)
	findings = append(findings, analyzer.NewNativeAddonAnalyzer().Analyze(d)...)

	// Sort by severity using the same ordering as model.SortFindings.
	sortCodeFindings(findings)

	return &Analysis{
		Diff:     d,
		Findings: findings,
	}
}

func sortCodeFindings(findings []model.CodeFinding) {
	order := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && order[findings[j].Severity] < order[findings[j-1].Severity]; j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}
