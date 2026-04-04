package analyzer

import (
	"fmt"
	"regexp"

	"github.com/chainrecon/chainrecon/internal/model"
)

// NetworkAnalyzer detects introduction of network capabilities in JS/TS files.
// Packages that suddenly start making HTTP requests or opening sockets are
// worth investigating, especially if the package had no networking before.
type NetworkAnalyzer interface {
	// Analyze scans added and modified JS/TS files for network access patterns.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// networkAnalyzer is the default implementation of NetworkAnalyzer.
type networkAnalyzer struct{}

// NewNetworkAnalyzer returns a new NetworkAnalyzer.
func NewNetworkAnalyzer() NetworkAnalyzer {
	return &networkAnalyzer{}
}

// networkPatterns matches require/import of networking modules, fetch calls,
// XMLHttpRequest, and net.Socket/net.connect usage.
var networkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`require\s*\(\s*['"](?:https?|net|dgram|dns)['"]\s*\)`),
	regexp.MustCompile(`(?:from|import)\s+['"](?:https?|net|dgram|dns)['"]`),
	regexp.MustCompile(`\bfetch\s*\(`),
	regexp.MustCompile(`\bXMLHttpRequest\b`),
	regexp.MustCompile(`\bnet\.Socket\b`),
	regexp.MustCompile(`\bnet\.connect\b`),
}

// Analyze checks added and modified JS/TS files for network access. If the
// old version of a modified file had no network calls but the new version
// does, that gets a HIGH severity. Otherwise it is MEDIUM.
func (n *networkAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	var findings []model.CodeFinding

	// Added files: if a new file has network calls, we check whether the
	// package had any networking before. Since the file is brand new, there
	// is no "old content" to compare, so we treat it as new capability.
	for _, f := range diff.Added {
		if !isJSFile(f.Path) {
			continue
		}
		matches := matchNetworkPatterns(f.NewContent)
		if len(matches) == 0 {
			continue
		}
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityHigh,
			Signal:   "network_access",
			Message:  "New file introduces network access",
			Detail:   fmt.Sprintf("patterns found: %s", joinUnique(matches)),
			File:     f.Path,
		})
	}

	// Modified files: compare old vs new content.
	for _, f := range diff.Modified {
		if !isJSFile(f.Path) {
			continue
		}
		newMatches := matchNetworkPatterns(f.NewContent)
		if len(newMatches) == 0 {
			continue
		}
		oldMatches := matchNetworkPatterns(f.OldContent)
		if len(oldMatches) == 0 {
			// File had no network calls before, now it does.
			findings = append(findings, model.CodeFinding{
				Severity: model.SeverityHigh,
				Signal:   "network_access",
				Message:  "Network access introduced in previously non-networking file",
				Detail:   fmt.Sprintf("patterns found: %s", joinUnique(newMatches)),
				File:     f.Path,
			})
		} else {
			// File already had network calls, but they changed.
			findings = append(findings, model.CodeFinding{
				Severity: model.SeverityMedium,
				Signal:   "network_access",
				Message:  "Network access patterns modified",
				Detail:   fmt.Sprintf("patterns found: %s", joinUnique(newMatches)),
				File:     f.Path,
			})
		}
	}

	return findings
}

// matchNetworkPatterns returns the list of pattern descriptions that match
// against the given content.
func matchNetworkPatterns(content []byte) []string {
	src := string(content)
	var matched []string
	seen := make(map[string]bool)
	for _, pat := range networkPatterns {
		if pat.MatchString(src) {
			label := pat.String()
			if !seen[label] {
				seen[label] = true
				matched = append(matched, label)
			}
		}
	}
	return matched
}

// joinUnique joins string slices with ", ".
func joinUnique(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += ", " + s
	}
	return out
}
