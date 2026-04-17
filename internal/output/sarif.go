package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/jakeva/chainrecon/internal/model"
)

// SARIFFormatter renders a Report as SARIF 2.1.0 JSON for GitHub code scanning.
type SARIFFormatter struct {
	version string
}

// NewSARIFFormatter returns a new SARIFFormatter with the given tool version.
func NewSARIFFormatter(version string) *SARIFFormatter {
	return &SARIFFormatter{version: version}
}

// Format serialises the report as a SARIF 2.1.0 document.
func (f *SARIFFormatter) Format(report *model.Report) (string, error) {
	rules := buildRules(report.Findings)
	results := buildResults(report)

	sarif := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "chainrecon",
					Version: f.version,
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", fmt.Errorf("sarif format: %w", err)
	}
	return string(data), nil
}

func buildRules(findings []model.Finding) []sarifRule {
	seen := map[string]bool{}
	var rules []sarifRule

	for _, f := range findings {
		id := ruleID(f)
		if seen[id] {
			continue
		}
		seen[id] = true

		rules = append(rules, sarifRule{
			ID:               id,
			ShortDescription: sarifText{Text: f.Message},
			DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
			Properties:       sarifRuleProps{SecuritySeverity: securitySeverity(f.Severity)},
		})
	}
	return rules
}

func buildResults(report *model.Report) []sarifResult {
	results := make([]sarifResult, 0, len(report.Findings))

	for _, f := range report.Findings {
		detail := f.Message
		if f.Detail != "" {
			detail = f.Message + ": " + f.Detail
		}

		results = append(results, sarifResult{
			RuleID:  ruleID(f),
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: detail},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifact{URI: "package.json"},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fingerprint(report.Package, f),
			},
		})
	}
	return results
}

func ruleID(f model.Finding) string {
	return fmt.Sprintf("chainrecon/%s/%s", f.Signal, sarifLevel(f.Severity))
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.0"
	case model.SeverityHigh:
		return "7.0"
	case model.SeverityMedium:
		return "4.0"
	case model.SeverityLow:
		return "2.0"
	default:
		return "1.0"
	}
}

func fingerprint(pkg string, f model.Finding) string {
	h := sha256.Sum256([]byte(pkg + "|" + f.Signal + "|" + f.Message))
	return fmt.Sprintf("%x", h[:8])
}

// SARIF 2.1.0 types.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
