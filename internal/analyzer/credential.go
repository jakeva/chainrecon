package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// CredentialAnalyzer detects code that reads credentials or sensitive files.
// Exfiltration attacks typically read tokens from environment variables or
// files like ~/.npmrc and then send them to an attacker controlled server.
type CredentialAnalyzer interface {
	// Analyze scans added and modified JS/TS files for credential access.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// credentialAnalyzer is the default implementation of CredentialAnalyzer.
type credentialAnalyzer struct{}

// NewCredentialAnalyzer returns a new CredentialAnalyzer.
func NewCredentialAnalyzer() CredentialAnalyzer {
	return &credentialAnalyzer{}
}

// Credential access patterns.
var (
	reProcessEnv = regexp.MustCompile(`process\.env\b`)
	reSensitiveEnvVar = regexp.MustCompile(
		`process\.env\s*(?:\.\s*|(?:\[\s*['"]))(NPM_TOKEN|GITHUB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)`,
	)
)

// sensitivePaths are file system paths commonly targeted for credential theft.
var sensitivePaths = []string{
	"~/.ssh",
	"~/.npmrc",
	"~/.gitconfig",
	"~/.aws/credentials",
	".ssh",
	".npmrc",
	".gitconfig",
	".aws/credentials",
}

// reHomedir matches os.homedir() which is often combined with sensitive path
// lookups in exfiltration code.
var reHomedir = regexp.MustCompile(`(?:os\.homedir|require\s*\(\s*['"]os['"]\s*\))`)

// Analyze inspects added and modified JS/TS files for credential access
// patterns. When credential reading and network access appear in the same
// file, the severity is CRITICAL because that is the classic exfiltration
// pattern.
func (c *credentialAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	var findings []model.CodeFinding

	candidates := collectJSFiles(diff)
	for _, cf := range candidates {
		findings = append(findings, c.scanFile(cf.path, cf.content)...)
	}

	return findings
}

// scanFile checks a single file for credential access and, if found, also
// checks whether network access exists in the same file to escalate severity.
func (c *credentialAnalyzer) scanFile(path string, content []byte) []model.CodeFinding {
	src := string(content)

	var signals []string

	// Check for sensitive env var access specifically.
	if reSensitiveEnvVar.MatchString(src) {
		matches := reSensitiveEnvVar.FindAllStringSubmatch(src, -1)
		for _, m := range matches {
			if len(m) > 1 {
				signals = appendUnique(signals, fmt.Sprintf("process.env.%s", m[1]))
			}
		}
	} else if reProcessEnv.MatchString(src) {
		signals = appendUnique(signals, "process.env access")
	}

	// Check for sensitive file path references.
	for _, sp := range sensitivePaths {
		if strings.Contains(src, sp) {
			signals = appendUnique(signals, fmt.Sprintf("reference to %s", sp))
		}
	}

	// Check for os.homedir() combined with sensitive path strings.
	if reHomedir.MatchString(src) {
		for _, sp := range sensitivePaths {
			// Strip the ~/ prefix for path join style access.
			trimmed := strings.TrimPrefix(sp, "~/")
			if strings.Contains(src, trimmed) {
				signals = appendUnique(signals, fmt.Sprintf("os.homedir() with %s", trimmed))
			}
		}
	}

	if len(signals) == 0 {
		return nil
	}

	// Check for network access in the same file. If both credential access
	// and network calls appear together, this looks like exfiltration.
	hasNetwork := len(matchNetworkPatterns(content)) > 0

	detail := strings.Join(signals, ", ")

	if hasNetwork {
		return []model.CodeFinding{{
			Severity: model.SeverityCritical,
			Signal:   "credential_access",
			Message:  "Credential access combined with network call",
			Detail:   detail,
			File:     path,
		}}
	}

	return []model.CodeFinding{{
		Severity: model.SeverityHigh,
		Signal:   "credential_access",
		Message:  "Credential or sensitive file access detected",
		Detail:   detail,
		File:     path,
	}}
}

// appendUnique appends s to the slice only if it is not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
