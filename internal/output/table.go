// Package output provides formatters for rendering chainrecon reports.
package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/chainrecon/chainrecon/internal/format"
	"github.com/chainrecon/chainrecon/internal/model"
)

// Column widths for the signal table.
const (
	colSignal = 23
	colScore  = 9
	colDetail = 43
)

// TableFormatter renders a Report as a styled terminal table using lipgloss.
type TableFormatter struct {
	bold     lipgloss.Style
	critical lipgloss.Style
	high     lipgloss.Style
	medium   lipgloss.Style
	low      lipgloss.Style
	info     lipgloss.Style
}

// NewTableFormatter returns a TableFormatter configured with default styles.
func NewTableFormatter() *TableFormatter {
	return &TableFormatter{
		bold:     lipgloss.NewStyle().Bold(true),
		critical: lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		high:     lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		medium:   lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		low:      lipgloss.NewStyle().Foreground(lipgloss.Color("12")),
		info:     lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// Format renders the report as a styled terminal table with key findings.
func (t *TableFormatter) Format(report *model.Report) (string, error) {
	var b strings.Builder

	// Header section.
	b.WriteString(t.renderHeader(report))
	b.WriteString("\n")

	// Signal table.
	b.WriteString(t.renderSignalTable(report))
	b.WriteString("\n")

	// Key findings.
	b.WriteString(t.renderFindings(report.Findings))

	return b.String(), nil
}

// renderHeader produces the package name, version, and weekly download lines.
func (t *TableFormatter) renderHeader(report *model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s\n", t.bold.Render("Package:"), report.Package)
	fmt.Fprintf(&b, " %s %s\n", t.bold.Render("Version:"), report.Version)
	fmt.Fprintf(&b, " %s %s\n", t.bold.Render("Weekly Downloads:"), format.Commas(report.WeeklyDownloads))
	return b.String()
}

// signalRow holds the data for a single signal table row.
type signalRow struct {
	signal string
	score  string
	detail string
}

// renderSignalTable draws the bordered table of signal scores and summary.
func (t *TableFormatter) renderSignalTable(report *model.Report) string {
	signals := t.buildSignalRows(report)
	summaries := t.buildSummaryRows(report)

	var b strings.Builder

	// Top border and header.
	b.WriteString(t.topRule())
	b.WriteString(t.renderRow(signalRow{signal: "Signal", score: "Score", detail: "Detail"}))
	b.WriteString(t.midRule())

	// Signal rows.
	for _, row := range signals {
		b.WriteString(t.renderRow(row))
	}

	// Mid-rule separating signals from summary.
	b.WriteString(t.midRule())

	// Summary rows.
	for _, row := range summaries {
		b.WriteString(t.renderRow(row))
	}

	// Bottom border.
	b.WriteString(t.bottomRule())

	return b.String()
}

// buildSignalRows returns the individual signal rows from the report scores.
func (t *TableFormatter) buildSignalRows(report *model.Report) []signalRow {
	detailBySignal := make(map[string]string)
	for _, f := range report.Findings {
		if _, ok := detailBySignal[f.Signal]; !ok {
			detailBySignal[f.Signal] = f.Message
		}
	}

	rows := []signalRow{
		{signal: "Provenance", score: fmt.Sprintf("%.1f/10", report.Scores.Provenance), detail: detailBySignal["provenance"]},
		{signal: "Publishing Hygiene", score: fmt.Sprintf("%.1f/10", report.Scores.PublishingHygiene), detail: detailBySignal["publishing_hygiene"]},
		{signal: "Maintainer Risk", score: fmt.Sprintf("%.1f/10", report.Scores.MaintainerRisk), detail: detailBySignal["maintainer_risk"]},
		{signal: "Identity Stability", score: fmt.Sprintf("%.1f/10", report.Scores.IdentityStability), detail: detailBySignal["identity"]},
		{signal: "Scorecard (imported)", score: fmt.Sprintf("%.1f/10", report.Scores.ScorecardRepo), detail: detailBySignal["scorecard"]},
		{signal: "Blast Radius", score: fmt.Sprintf("%.1f/10", report.Scores.BlastRadius), detail: detailBySignal["blast_radius"]},
	}
	return rows
}

// buildSummaryRows returns the aggregate rows (attack surface and target score).
func (t *TableFormatter) buildSummaryRows(report *model.Report) []signalRow {
	targetLabel := targetLabel(report.Scores.TargetScore)
	return []signalRow{
		{signal: "Attack Surface", score: fmt.Sprintf("%.1f/10", report.Scores.AttackSurface), detail: ""},
		{signal: "Target Score", score: fmt.Sprintf("%.1f", report.Scores.TargetScore), detail: targetLabel},
	}
}

// renderRow renders a single data row, word-wrapping the detail column as
// needed and producing multiple lines when the text overflows.
func (t *TableFormatter) renderRow(row signalRow) string {
	detailLines := wrapText(row.detail, colDetail)
	if len(detailLines) == 0 {
		detailLines = []string{""}
	}

	var b strings.Builder
	for i, dl := range detailLines {
		sig := ""
		sc := ""
		if i == 0 {
			sig = row.signal
			sc = row.score
		}
		fmt.Fprintf(&b, " │ %s │ %s │ %s │\n",
			padRight(sig, colSignal),
			padRight(sc, colScore),
			padRight(dl, colDetail),
		)
	}
	return b.String()
}

// topRule returns the top border of the table.
func (t *TableFormatter) topRule() string {
	return fmt.Sprintf(" ┌%s┬%s┬%s┐\n",
		strings.Repeat("─", colSignal+2),
		strings.Repeat("─", colScore+2),
		strings.Repeat("─", colDetail+2),
	)
}

// midRule returns a mid-table horizontal separator.
func (t *TableFormatter) midRule() string {
	return fmt.Sprintf(" ├%s┼%s┼%s┤\n",
		strings.Repeat("─", colSignal+2),
		strings.Repeat("─", colScore+2),
		strings.Repeat("─", colDetail+2),
	)
}

// bottomRule returns the bottom border of the table.
func (t *TableFormatter) bottomRule() string {
	return fmt.Sprintf(" └%s┴%s┴%s┘\n",
		strings.Repeat("─", colSignal+2),
		strings.Repeat("─", colScore+2),
		strings.Repeat("─", colDetail+2),
	)
}


// renderFindings produces the "Key Findings" section with colored severity tags.
func (t *TableFormatter) renderFindings(findings []model.Finding) string {
	if len(findings) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, " %s\n", t.bold.Render("Key Findings:"))
	for _, f := range findings {
		tag := t.colorSeverity(f.Severity)
		fmt.Fprintf(&b, "  %s %s\n", tag, f.Message)
	}
	return b.String()
}

// colorSeverity returns the severity label wrapped in brackets and styled
// with the appropriate color for terminal display.
func (t *TableFormatter) colorSeverity(sev model.Severity) string {
	label := "[" + string(sev) + "]"
	switch sev {
	case model.SeverityCritical:
		return t.critical.Render(label)
	case model.SeverityHigh:
		return t.high.Render(label)
	case model.SeverityMedium:
		return t.medium.Render(label)
	case model.SeverityLow:
		return t.low.Render(label)
	case model.SeverityInfo:
		return t.info.Render(label)
	default:
		return label
	}
}

// targetLabel returns a human-readable risk category for the given target score.
func targetLabel(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	default:
		return "LOW"
	}
}


// wrapText splits text into lines that fit within the given width, breaking
// on word boundaries. Lines are never wider than width characters.
func wrapText(text string, width int) []string {
	if text == "" {
		return nil
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	current := words[0]
	for _, w := range words[1:] {
		if len(current)+1+len(w) > width {
			lines = append(lines, current)
			current = w
		} else {
			current += " " + w
		}
	}
	lines = append(lines, current)
	return lines
}

// padRight pads s with trailing spaces so that it occupies exactly width
// visible characters. Uses lipgloss.Width to correctly measure strings
// that contain ANSI escape sequences or wide unicode characters.
func padRight(s string, width int) string {
	n := lipgloss.Width(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}
