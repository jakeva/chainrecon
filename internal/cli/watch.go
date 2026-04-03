package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/scan"
	"github.com/chainrecon/chainrecon/internal/state"
	"github.com/chainrecon/chainrecon/internal/watch"
	"github.com/chainrecon/chainrecon/internal/watchlist"
	"github.com/spf13/cobra"
)

// NewWatchCmd creates a cobra command that monitors packages for new versions.
func NewWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Monitor packages for new versions and scan them",
		Long: `Watch reads a watchlist file and polls npm for new versions of each
package. When a new version is detected, it runs a full scan. Exits with
code 1 if any package exceeds its threshold.

Use --once for a single pass (CI mode) or omit it for continuous polling.`,
		RunE: runWatch,
	}

	cmd.Flags().String("config", ".chainrecon.yml", "Path to watchlist YAML file")
	cmd.Flags().Bool("once", false, "Run a single pass and exit")
	cmd.Flags().String("state-file", "", "Path to state file for persistence between runs")
	cmd.Flags().Int("depth", 20, "How many versions back to analyze")
	cmd.Flags().Duration("timeout", 2*time.Minute, "Per-scan timeout")
	cmd.Flags().String("github-token", "", "GitHub personal access token (or set GITHUB_TOKEN)")
	cmd.Flags().Bool("no-scorecard", false, "Skip OpenSSF Scorecard lookup")
	cmd.Flags().Bool("no-github", false, "Skip GitHub tag correlation")

	return cmd
}

func runWatch(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	configPath, _ := cmd.Flags().GetString("config")
	once, _ := cmd.Flags().GetBool("once")
	stateFile, _ := cmd.Flags().GetString("state-file")
	depth, _ := cmd.Flags().GetInt("depth")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	githubToken, _ := cmd.Flags().GetString("github-token")
	noScorecard, _ := cmd.Flags().GetBool("no-scorecard")
	noGitHub, _ := cmd.Flags().GetBool("no-github")
	noCache, _ := cmd.Root().PersistentFlags().GetBool("no-cache")

	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	wl, err := watchlist.Load(configPath)
	if err != nil {
		return err
	}

	// Load persisted state if a state file is configured.
	var st *state.State
	if stateFile != "" {
		st, err = state.Load(stateFile)
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
	} else {
		st = state.New()
	}

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
	}

	poller := npm.NewPoller()
	scanOpts := scan.Options{
		Depth:       depth,
		Timeout:     timeout,
		GitHubToken: githubToken,
		NoScorecard: noScorecard,
		NoGitHub:    noGitHub,
		NoCache:     noCache,
		UserAgent:   "chainrecon/" + Version,
	}
	scanFn := watch.DefaultScanFunc(scanOpts)

	runner := watch.NewRunner(wl, poller, scanFn, st, logf)

	// Set up context with signal handling for graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var alerts []watch.Alert
	if once {
		alerts, err = runner.RunOnce(ctx)
	} else {
		alerts, err = runner.RunContinuous(ctx)
	}

	// Persist state if configured, even on error.
	if stateFile != "" {
		if saveErr := state.Save(stateFile, runner.State()); saveErr != nil {
			logf("Warning: failed to save state: %v\n", saveErr)
		}
	}

	if err != nil {
		return err
	}

	if len(alerts) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d package(s) exceeded threshold:\n", len(alerts))
		for _, a := range alerts {
			fmt.Fprintf(os.Stderr, "  %s@%s: score %.1f (threshold %.1f)\n",
				a.Package, a.Version, a.TargetScore, a.Threshold)
		}
		return fmt.Errorf("%d package(s) exceeded threshold", len(alerts))
	}

	return nil
}
