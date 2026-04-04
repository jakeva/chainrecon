package analyzer

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// ObfuscationAnalyzer scans added or modified JS/TS files for patterns that
// indicate obfuscated code: eval calls, base64/hex encoded payloads, high
// entropy strings, and String.fromCharCode usage.
type ObfuscationAnalyzer interface {
	// Analyze inspects JS/TS files in the diff for obfuscation signals.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// obfuscationAnalyzer is the default implementation of ObfuscationAnalyzer.
type obfuscationAnalyzer struct{}

// NewObfuscationAnalyzer returns a new ObfuscationAnalyzer.
func NewObfuscationAnalyzer() ObfuscationAnalyzer {
	return &obfuscationAnalyzer{}
}

// Regex patterns for the individual obfuscation signals.
var (
	reEval           = regexp.MustCompile(`\beval\s*\(`)
	reBufferFrom     = regexp.MustCompile(`Buffer\.from\s*\([^)]*(?:base64|hex)[^)]*\)`)
	reHexPayload     = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){10,}`)
	reFromCharCode   = regexp.MustCompile(`String\.fromCharCode\s*\(`)
	reHighEntropyStr = regexp.MustCompile(`["']([^"']{41,})["']`)
)

// entropyThreshold is the minimum Shannon entropy for a string to be flagged.
const entropyThreshold = 4.5

// Analyze scans all added and modified JS/TS files. If eval appears alongside
// another obfuscation signal in the same file, the finding is HIGH severity.
// Individual signals on their own are MEDIUM.
func (o *obfuscationAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	var findings []model.CodeFinding

	candidates := collectJSFiles(diff)
	for _, cf := range candidates {
		findings = append(findings, o.scanFile(cf.path, cf.content)...)
	}

	return findings
}

// candidateFile is a file path + content pair for scanning.
type candidateFile struct {
	path    string
	content []byte
}

// collectJSFiles gathers the JS/TS files from added and modified lists. For
// modified files we use the new content since that is what will actually run.
func collectJSFiles(diff *model.ReleaseDiff) []candidateFile {
	var out []candidateFile
	for _, f := range diff.Added {
		if isJSFile(f.Path) {
			out = append(out, candidateFile{path: f.Path, content: f.NewContent})
		}
	}
	for _, f := range diff.Modified {
		if isJSFile(f.Path) {
			out = append(out, candidateFile{path: f.Path, content: f.NewContent})
		}
	}
	return out
}

// scanFile checks a single file for all obfuscation patterns and returns
// the appropriate findings.
func (o *obfuscationAnalyzer) scanFile(path string, content []byte) []model.CodeFinding {
	src := string(content)

	hasEval := reEval.MatchString(src)
	hasBufferFrom := reBufferFrom.MatchString(src)
	hasHexPayload := reHexPayload.MatchString(src)
	hasFromCharCode := reFromCharCode.MatchString(src)
	hasHighEntropy := containsHighEntropyString(src)

	otherSignals := hasBufferFrom || hasHexPayload || hasFromCharCode || hasHighEntropy

	var findings []model.CodeFinding

	// When eval appears with another signal in the same file, that is a
	// strong indicator of intentional obfuscation.
	if hasEval && otherSignals {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityHigh,
			Signal:   "obfuscation",
			Message:  "eval() combined with other obfuscation patterns",
			Detail:   describeSignals(hasBufferFrom, hasHexPayload, hasFromCharCode, hasHighEntropy),
			File:     path,
		})
		return findings
	}

	if hasEval {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityMedium,
			Signal:   "obfuscation",
			Message:  "eval() call detected",
			File:     path,
		})
	}
	if hasBufferFrom {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityMedium,
			Signal:   "obfuscation",
			Message:  "Buffer.from with base64/hex encoding detected",
			File:     path,
		})
	}
	if hasHexPayload {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityMedium,
			Signal:   "obfuscation",
			Message:  "Hex encoded payload detected",
			File:     path,
		})
	}
	if hasFromCharCode {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityMedium,
			Signal:   "obfuscation",
			Message:  "String.fromCharCode usage detected",
			File:     path,
		})
	}
	if hasHighEntropy {
		findings = append(findings, model.CodeFinding{
			Severity: model.SeverityMedium,
			Signal:   "obfuscation",
			Message:  "High entropy string detected",
			File:     path,
		})
	}

	return findings
}

// containsHighEntropyString checks whether any quoted string longer than 40
// characters has Shannon entropy above the threshold.
func containsHighEntropyString(src string) bool {
	matches := reHighEntropyStr.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		if shannonEntropy(m[1]) > entropyThreshold {
			return true
		}
	}
	return false
}

// shannonEntropy computes the Shannon entropy (bits per character) for s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// describeSignals builds a human readable summary of which secondary signals
// were found alongside eval.
func describeSignals(bufferFrom, hexPayload, fromCharCode, highEntropy bool) string {
	var parts []string
	if bufferFrom {
		parts = append(parts, "Buffer.from encoding")
	}
	if hexPayload {
		parts = append(parts, "hex payload")
	}
	if fromCharCode {
		parts = append(parts, "String.fromCharCode")
	}
	if highEntropy {
		parts = append(parts, "high entropy string")
	}
	return fmt.Sprintf("eval() found with: %s", strings.Join(parts, ", "))
}
