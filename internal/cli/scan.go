package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chainrecon/chainrecon/internal/output"
	"github.com/chainrecon/chainrecon/internal/scan"
	"github.com/spf13/cobra"
)

// NewScanCmd creates a cobra command that orchestrates a full package scan.
func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <package[@version]>",
		Short: "Scan an npm package for supply chain risk signals",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}

	cmd.Flags().Int("depth", 20, "How many versions back to analyze for provenance history")
	cmd.Flags().String("format", "table", "Output format: table, json, sarif")
	cmd.Flags().Duration("timeout", 2*time.Minute, "Timeout for the entire scan")
	cmd.Flags().String("github-token", "", "GitHub personal access token (or set GITHUB_TOKEN)")
	cmd.Flags().Bool("no-scorecard", false, "Skip OpenSSF Scorecard lookup")
	cmd.Flags().Bool("no-github", false, "Skip GitHub tag correlation")
	cmd.Flags().Float64("threshold", 0, "Exit with code 1 if target score meets or exceeds this value")

	return cmd
}

// runScan is the RunE handler for the scan command.
func runScan(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	packageName, requestedVersion := parsePackageArg(args[0])

	depth, _ := cmd.Flags().GetInt("depth")
	formatFlag, _ := cmd.Flags().GetString("format")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	noCache, _ := cmd.Root().PersistentFlags().GetBool("no-cache")
	githubToken, _ := cmd.Flags().GetString("github-token")
	noScorecard, _ := cmd.Flags().GetBool("no-scorecard")
	noGitHub, _ := cmd.Flags().GetBool("no-github")
	threshold, _ := cmd.Flags().GetFloat64("threshold")

	if depth < 1 {
		return fmt.Errorf("--depth must be at least 1")
	}

	formatFlag = strings.ToLower(formatFlag)
	switch formatFlag {
	case "table", "json", "sarif":
	default:
		return fmt.Errorf("--format must be \"table\", \"json\", or \"sarif\", got %q", formatFlag)
	}

	quiet := formatFlag != "table"

	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Build log function that respects quiet mode.
	var logf func(string, ...any)
	if quiet {
		logf = nil
	} else {
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		}
	}

	report, err := scan.Run(ctx, packageName, requestedVersion, scan.Options{
		Depth:       depth,
		Timeout:     timeout,
		GitHubToken: githubToken,
		NoScorecard: noScorecard,
		NoGitHub:    noGitHub,
		NoCache:     noCache,
		UserAgent:   "chainrecon/" + Version,
		LogFunc:     logf,
	})
	if err != nil {
		return err
	}

	// Format output.
	var formatter output.Formatter
	switch formatFlag {
	case "json":
		formatter = output.NewJSONFormatter()
	case "sarif":
		formatter = output.NewSARIFFormatter(Version)
	default:
		formatter = output.NewTableFormatter()
	}

	result, err := formatter.Format(report)
	if err != nil {
		return fmt.Errorf("format output: %w", err)
	}

	_, _ = fmt.Fprint(os.Stdout, result)
	_, _ = fmt.Fprintln(os.Stdout)

	// Threshold check.
	if threshold > 0 && report.Scores.TargetScore >= threshold {
		return fmt.Errorf("target score %.1f meets or exceeds threshold %.1f", report.Scores.TargetScore, threshold)
	}

	return nil
}

// parsePackageArg splits a package argument of the form "name" or "name@version"
// into its components. For scoped packages (e.g. @scope/pkg@1.0.0) the scope is
// preserved in the package name.
func parsePackageArg(arg string) (name, version string) {
	if strings.HasPrefix(arg, "@") {
		rest := arg[1:]
		idx := strings.Index(rest, "@")
		if idx == -1 {
			return arg, ""
		}
		return arg[:idx+1], rest[idx+1:]
	}

	idx := strings.Index(arg, "@")
	if idx == -1 {
		return arg, ""
	}
	return arg[:idx], arg[idx+1:]
}
