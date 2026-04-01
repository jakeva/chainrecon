package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/chainrecon/chainrecon/internal/analyzer"
	"github.com/chainrecon/chainrecon/internal/cache"
	gh "github.com/chainrecon/chainrecon/internal/collector/github"
	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/collector/scorecard"
	"github.com/chainrecon/chainrecon/internal/model"
	"github.com/chainrecon/chainrecon/internal/output"
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
	cmd.Flags().String("format", "table", "Output format: table, json")
	cmd.Flags().Duration("timeout", 2*time.Minute, "Timeout for the entire scan")
	cmd.Flags().String("github-token", "", "GitHub personal access token (or set GITHUB_TOKEN)")
	cmd.Flags().Bool("no-scorecard", false, "Skip OpenSSF Scorecard lookup")
	cmd.Flags().Bool("no-github", false, "Skip GitHub tag correlation")

	return cmd
}

// runScan is the RunE handler for the scan command.
func runScan(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// Parse the package argument: name[@version].
	packageName, requestedVersion := parsePackageArg(args[0])

	depth, _ := cmd.Flags().GetInt("depth")
	formatFlag, _ := cmd.Flags().GetString("format")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	noCache, _ := cmd.Root().PersistentFlags().GetBool("no-cache")
	githubToken, _ := cmd.Flags().GetString("github-token")
	noScorecard, _ := cmd.Flags().GetBool("no-scorecard")
	noGitHub, _ := cmd.Flags().GetBool("no-github")

	if depth < 1 {
		return fmt.Errorf("--depth must be at least 1")
	}

	switch strings.ToLower(formatFlag) {
	case "table", "json":
	default:
		return fmt.Errorf("--format must be \"table\" or \"json\", got %q", formatFlag)
	}

	// Fall back to GITHUB_TOKEN env var.
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	npm.SetUserAgent("chainrecon/" + Version)

	// --- Cache setup ---
	var store cache.Store
	if noCache {
		store = cache.NopStore{}
	} else {
		bs, err := cache.NewBoltStore()
		if err != nil {
			return fmt.Errorf("init cache: %w", err)
		}
		store = bs
	}
	defer func() { _ = store.Close() }()

	// --- Clients ---
	registry := npm.NewRegistryClient(store)
	attestClient := npm.NewAttestationClient(store)
	scorecardClient := scorecard.NewClient(store)
	githubClient := gh.NewClient(store, githubToken)

	// --- Fetch package metadata ---
	fmt.Fprintf(os.Stderr, "Fetching metadata for %s ...\n", packageName)
	metadata, err := registry.FetchPackageMetadata(ctx, packageName)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}

	// --- Determine target version ---
	targetVersion := requestedVersion
	if targetVersion == "" {
		if latest, ok := metadata.DistTags["latest"]; ok {
			targetVersion = latest
		} else {
			return fmt.Errorf("no version specified and no 'latest' dist-tag found for %s", packageName)
		}
	}
	fmt.Fprintf(os.Stderr, "Target version: %s\n", targetVersion)

	// --- Collect sorted versions up to --depth ---
	sortedVersions := registry.GetSortedVersions(metadata)
	if len(sortedVersions) > depth {
		sortedVersions = sortedVersions[:depth]
	}

	// --- Resolve GitHub repo for Scorecard and tag correlation ---
	repoOwner, repoName := gh.ParseRepoURL(metadata)
	hasGitHubRepo := repoOwner != "" && repoName != ""

	// --- Fetch all data in parallel ---
	fmt.Fprintf(os.Stderr, "Fetching attestations, downloads, dependents")
	if hasGitHubRepo && !noScorecard {
		fmt.Fprintf(os.Stderr, ", scorecard")
	}
	if hasGitHubRepo && !noGitHub {
		fmt.Fprintf(os.Stderr, ", releases")
	}
	fmt.Fprintf(os.Stderr, " ...\n")

	var (
		attestations    []model.VersionAttestation
		downloads       *model.DownloadCount
		dependentCount  int
		scorecardResult *model.ScorecardResult
		githubReleases  []model.GitHubRelease
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		attestations, err = attestClient.FetchVersionAttestations(gctx, packageName, sortedVersions)
		if err != nil {
			return fmt.Errorf("fetch attestations: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		var err error
		downloads, err = registry.FetchDownloadCounts(gctx, packageName)
		if err != nil {
			return fmt.Errorf("fetch downloads: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		var err error
		dependentCount, err = registry.FetchDependentCount(gctx, packageName)
		if err != nil {
			return fmt.Errorf("fetch dependent count: %w", err)
		}
		return nil
	})

	if hasGitHubRepo && !noScorecard {
		g.Go(func() error {
			var err error
			scorecardResult, err = scorecardClient.FetchScore(gctx, repoOwner, repoName)
			if err != nil {
				// Scorecard failures are non-fatal.
				fmt.Fprintf(os.Stderr, "Warning: scorecard lookup failed: %v\n", err)
				return nil
			}
			return nil
		})
	}

	if hasGitHubRepo && !noGitHub {
		g.Go(func() error {
			var err error
			githubReleases, err = githubClient.FetchReleases(gctx, repoOwner, repoName)
			if err != nil {
				// GitHub failures are non-fatal.
				fmt.Fprintf(os.Stderr, "Warning: GitHub release fetch failed: %v\n", err)
				return nil
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// --- Run analyzers ---
	fmt.Fprintf(os.Stderr, "Analyzing ...\n")

	provenanceAnalyzer := analyzer.NewProvenanceAnalyzer()
	provenanceScore, provenanceFindings := provenanceAnalyzer.Analyze(attestations)

	hygieneAnalyzer := analyzer.NewHygieneAnalyzer()
	hygieneScore, hygieneFindings := hygieneAnalyzer.Analyze(metadata, attestations)

	maintainerAnalyzer := analyzer.NewMaintainerAnalyzer()
	maintainerScore, maintainerFindings := maintainerAnalyzer.Analyze(metadata)

	blastAnalyzer := analyzer.NewBlastRadiusAnalyzer()
	blastScore, blastFindings := blastAnalyzer.Analyze(downloads.Downloads, dependentCount, packageName)

	identityAnalyzer := analyzer.NewIdentityAnalyzer()
	identityScore, identityFindings := identityAnalyzer.Analyze(metadata, sortedVersions)

	// Scorecard analysis.
	scorecardAnalyzer := analyzer.NewScorecardAnalyzer()
	scorecardScore, scorecardFindings := scorecardAnalyzer.Analyze(scorecardResult)

	// Tag correlation analysis.
	var tagFindings []model.Finding
	if githubReleases != nil {
		tagAnalyzer := analyzer.NewTagCorrelationAnalyzer()
		tagFindings = tagAnalyzer.Analyze(sortedVersions, githubReleases)
	}

	// --- Composite scoring ---
	s := analyzer.NewScorer()
	signalInputs := analyzer.SignalInputs{
		Provenance:        provenanceScore,
		PublishingHygiene: hygieneScore,
		MaintainerRisk:    maintainerScore,
		IdentityStability: identityScore,
		BlastRadius:       blastScore,
	}
	// Only include Scorecard in the weighted score if we have data or attempted lookup.
	if hasGitHubRepo && !noScorecard {
		signalInputs.Scorecard = &scorecardScore
	}
	scores := s.ComputeScores(signalInputs)

	// --- Build provenance history ---
	provenanceHistory := make([]model.ProvenanceVersion, 0, len(attestations))
	for _, a := range attestations {
		state := provenanceAnalyzer.ClassifyState([]model.VersionAttestation{a})
		provenanceHistory = append(provenanceHistory, model.ProvenanceVersion{
			Version:    a.Version,
			State:      state,
			HasSLSA:    a.HasSLSA,
			HasPublish: a.HasPublish,
		})
	}

	// --- Aggregate findings ---
	var allFindings []model.Finding
	allFindings = append(allFindings, provenanceFindings...)
	allFindings = append(allFindings, hygieneFindings...)
	allFindings = append(allFindings, maintainerFindings...)
	allFindings = append(allFindings, blastFindings...)
	allFindings = append(allFindings, identityFindings...)
	allFindings = append(allFindings, scorecardFindings...)
	allFindings = append(allFindings, tagFindings...)

	// --- Build report ---
	report := &model.Report{
		Package:           packageName,
		Version:           targetVersion,
		Timestamp:         time.Now().UTC(),
		Scores:            scores,
		Findings:          allFindings,
		ProvenanceHistory: provenanceHistory,
		Maintainers:       metadata.Maintainers,
		WeeklyDownloads:   downloads.Downloads,
		DependentCount:    dependentCount,
	}

	// --- Format output ---
	var formatter output.Formatter
	switch strings.ToLower(formatFlag) {
	case "json":
		formatter = output.NewJSONFormatter()
	default:
		formatter = output.NewTableFormatter()
	}

	result, err := formatter.Format(report)
	if err != nil {
		return fmt.Errorf("format output: %w", err)
	}

	_, _ = fmt.Fprint(os.Stdout, result)
	_, _ = fmt.Fprintln(os.Stdout)

	return nil
}

// parsePackageArg splits a package argument of the form "name" or "name@version"
// into its components. For scoped packages (e.g. @scope/pkg@1.0.0) the scope is
// preserved in the package name.
func parsePackageArg(arg string) (name, version string) {
	// Handle scoped packages: @scope/pkg@version
	if strings.HasPrefix(arg, "@") {
		// Find the second @ which separates name from version.
		rest := arg[1:]
		idx := strings.Index(rest, "@")
		if idx == -1 {
			return arg, ""
		}
		return arg[:idx+1], rest[idx+1:]
	}

	// Unscoped: pkg@version
	idx := strings.Index(arg, "@")
	if idx == -1 {
		return arg, ""
	}
	return arg[:idx], arg[idx+1:]
}
