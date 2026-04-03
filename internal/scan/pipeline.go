// Package scan provides the core scanning pipeline for npm packages.
package scan

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/chainrecon/chainrecon/internal/analyzer"
	"github.com/chainrecon/chainrecon/internal/cache"
	gh "github.com/chainrecon/chainrecon/internal/collector/github"
	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/collector/scorecard"
	"github.com/chainrecon/chainrecon/internal/model"
)

// Options configures a scan pipeline run.
type Options struct {
	Depth       int
	Timeout     time.Duration
	GitHubToken string
	NoScorecard bool
	NoGitHub    bool
	NoCache     bool
	UserAgent   string
	LogFunc     func(format string, args ...any)
}

// Run executes the full scan pipeline for a package and returns the report.
// If version is empty, the latest dist-tag is used.
func Run(ctx context.Context, packageName, version string, opts Options) (*model.Report, error) {
	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if opts.UserAgent != "" {
		npm.SetUserAgent(opts.UserAgent)
	}

	// Cache setup.
	var store cache.Store
	if opts.NoCache {
		store = cache.NopStore{}
	} else {
		bs, err := cache.NewBoltStore()
		if err != nil {
			return nil, fmt.Errorf("init cache: %w", err)
		}
		store = bs
	}
	defer func() { _ = store.Close() }()

	// Clients.
	registry := npm.NewRegistryClient(store)
	attestClient := npm.NewAttestationClient(store)
	scorecardClient := scorecard.NewClient(store)
	githubClient := gh.NewClient(store, opts.GitHubToken)

	// Fetch package metadata.
	logf("Fetching metadata for %s ...\n", packageName)
	metadata, err := registry.FetchPackageMetadata(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}

	// Determine target version.
	targetVersion := version
	if targetVersion == "" {
		if latest, ok := metadata.DistTags["latest"]; ok {
			targetVersion = latest
		} else {
			return nil, fmt.Errorf("no version specified and no 'latest' dist-tag found for %s", packageName)
		}
	}
	logf("Target version: %s\n", targetVersion)

	// Collect sorted versions up to depth.
	sortedVersions := registry.GetSortedVersions(metadata)
	if len(sortedVersions) > opts.Depth {
		sortedVersions = sortedVersions[:opts.Depth]
	}

	// Resolve GitHub repo for Scorecard and tag correlation.
	repoOwner, repoName := gh.ParseRepoURL(metadata)
	hasGitHubRepo := repoOwner != "" && repoName != ""

	// Fetch all data in parallel.
	var (
		attestations    []model.VersionAttestation
		downloads       *model.DownloadCount
		dependentCount  int
		scorecardResult *model.ScorecardResult
		githubReleases  []model.GitHubRelease
		githubTags      []model.GitHubTag
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

	if hasGitHubRepo && !opts.NoScorecard {
		g.Go(func() error {
			var err error
			scorecardResult, err = scorecardClient.FetchScore(gctx, repoOwner, repoName)
			if err != nil {
				logf("Warning: scorecard lookup failed: %v\n", err)
				return nil
			}
			return nil
		})
	}

	if hasGitHubRepo && !opts.NoGitHub {
		g.Go(func() error {
			var err error
			githubReleases, err = githubClient.FetchReleases(gctx, repoOwner, repoName)
			if err != nil {
				logf("Warning: GitHub release fetch failed: %v\n", err)
				return nil
			}
			return nil
		})
		g.Go(func() error {
			var err error
			githubTags, err = githubClient.FetchTags(gctx, repoOwner, repoName)
			if err != nil {
				logf("Warning: GitHub tag fetch failed: %v\n", err)
				return nil
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Run analyzers.
	logf("Analyzing ...\n")

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

	scorecardAnalyzer := analyzer.NewScorecardAnalyzer()
	scorecardScore, scorecardFindings := scorecardAnalyzer.Analyze(scorecardResult)

	// Tag correlation analysis.
	var tagFindings []model.Finding
	if githubReleases != nil || githubTags != nil {
		merged := mergeReleasesAndTags(githubReleases, githubTags)
		tagAnalyzer := analyzer.NewTagCorrelationAnalyzer()
		tagFindings = tagAnalyzer.Analyze(sortedVersions, merged)
	}

	// Composite scoring.
	s := analyzer.NewScorer()
	signalInputs := analyzer.SignalInputs{
		Provenance:        provenanceScore,
		PublishingHygiene: hygieneScore,
		MaintainerRisk:    maintainerScore,
		IdentityStability: identityScore,
		BlastRadius:       blastScore,
	}
	if hasGitHubRepo && !opts.NoScorecard {
		signalInputs.Scorecard = &scorecardScore
	}
	scores := s.ComputeScores(signalInputs)

	// Build provenance history.
	provenanceHistory := make([]model.ProvenanceVersion, len(attestations))
	for i, a := range attestations {
		state := model.ProvenanceNever
		if a.HasAnyProvenance {
			state = model.ProvenanceActive
		}
		provenanceHistory[i] = model.ProvenanceVersion{
			Version:    a.Version,
			State:      state,
			HasSLSA:    a.HasSLSA,
			HasPublish: a.HasPublish,
		}
	}

	// Aggregate findings.
	var allFindings []model.Finding
	allFindings = append(allFindings, provenanceFindings...)
	allFindings = append(allFindings, hygieneFindings...)
	allFindings = append(allFindings, maintainerFindings...)
	allFindings = append(allFindings, blastFindings...)
	allFindings = append(allFindings, identityFindings...)
	allFindings = append(allFindings, scorecardFindings...)
	allFindings = append(allFindings, tagFindings...)
	model.SortFindings(allFindings)

	// Build report.
	var repoURL string
	if hasGitHubRepo {
		repoURL = fmt.Sprintf("https://github.com/%s/%s", repoOwner, repoName)
	}

	return &model.Report{
		Package:           packageName,
		Version:           targetVersion,
		Description:       metadata.Description,
		RepositoryURL:     repoURL,
		Timestamp:         time.Now().UTC(),
		Scores:            scores,
		Findings:          allFindings,
		ProvenanceHistory: provenanceHistory,
		Maintainers:       metadata.Maintainers,
		WeeklyDownloads:   downloads.Downloads,
		DependentCount:    dependentCount,
	}, nil
}

// mergeReleasesAndTags combines GitHub releases and git tags into a single
// deduplicated slice of GitHubRelease.
func mergeReleasesAndTags(releases []model.GitHubRelease, tags []model.GitHubTag) []model.GitHubRelease {
	seen := make(map[string]bool, len(releases)+len(tags))
	merged := make([]model.GitHubRelease, 0, len(releases)+len(tags))

	for _, r := range releases {
		if !seen[r.TagName] {
			seen[r.TagName] = true
			merged = append(merged, r)
		}
	}
	for _, t := range tags {
		if !seen[t.Name] {
			seen[t.Name] = true
			merged = append(merged, model.GitHubRelease{TagName: t.Name})
		}
	}
	return merged
}
