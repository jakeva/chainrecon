package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/jakeva/chainrecon/internal/collector/npm"
	pkgdiff "github.com/jakeva/chainrecon/internal/diff"
	"github.com/spf13/cobra"
)

// NewDiffCmd creates a cobra command that diffs two versions of a package.
func NewDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <package>",
		Short: "Diff two versions of an npm package for suspicious changes",
		Example: `  chainrecon diff express
  chainrecon diff lodash --old 4.17.20 --new 4.17.21
  chainrecon diff axios --new 1.7.0 --format json
  chainrecon diff @anthropic-ai/sdk --threshold 5`,
		Args: cobra.ExactArgs(1),
		RunE: runDiff,
	}

	cmd.Flags().String("old", "", "Old version to compare (default: version before --new)")
	cmd.Flags().String("new", "", "New version to compare (default: latest)")
	cmd.Flags().String("format", "table", "Output format: table, json")
	cmd.Flags().Float64("threshold", 0, "Exit with code 1 if finding count meets or exceeds this value")
	cmd.Flags().Duration("timeout", 2*time.Minute, "Timeout for the entire diff operation")

	return cmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	packageName := args[0]
	oldVersion, _ := cmd.Flags().GetString("old")
	newVersion, _ := cmd.Flags().GetString("new")
	formatFlag, _ := cmd.Flags().GetString("format")
	threshold, _ := cmd.Flags().GetFloat64("threshold")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
	}

	// Resolve versions from registry metadata.
	registry := npm.NewRegistryClient(noopCache{})
	meta, err := registry.FetchPackageMetadata(ctx, packageName)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}

	if newVersion == "" {
		latest, ok := meta.DistTags["latest"]
		if !ok {
			return fmt.Errorf("no 'latest' dist-tag for %s", packageName)
		}
		newVersion = latest
	}

	if oldVersion == "" {
		sorted := registry.GetSortedVersions(meta)
		oldVersion = findPreviousVersion(sorted, newVersion)
		if oldVersion == "" {
			return fmt.Errorf("could not determine previous version for %s@%s", packageName, newVersion)
		}
	}

	logf("Diffing %s: %s -> %s\n", packageName, oldVersion, newVersion)

	// Resolve tarball URLs.
	oldDetail, ok := meta.Versions[oldVersion]
	if !ok {
		return fmt.Errorf("version %s not found for %s", oldVersion, packageName)
	}
	newDetail, ok := meta.Versions[newVersion]
	if !ok {
		return fmt.Errorf("version %s not found for %s", newVersion, packageName)
	}

	oldURL := oldDetail.Dist.Tarball
	newURL := newDetail.Dist.Tarball

	if oldURL == "" {
		oldURL = defaultTarballURL(packageName, oldVersion)
	}
	if newURL == "" {
		newURL = defaultTarballURL(packageName, newVersion)
	}

	// Download and extract both tarballs.
	tc := npm.NewTarballClient()

	logf("Downloading %s@%s ...\n", packageName, oldVersion)
	oldContents, err := tc.FetchContents(ctx, packageName, oldVersion, oldURL)
	if err != nil {
		return fmt.Errorf("fetch old tarball: %w", err)
	}

	logf("Downloading %s@%s ...\n", packageName, newVersion)
	newContents, err := tc.FetchContents(ctx, packageName, newVersion, newURL)
	if err != nil {
		return fmt.Errorf("fetch new tarball: %w", err)
	}

	// Diff and analyze.
	logf("Comparing ...\n")
	relDiff := pkgdiff.Compare(oldContents, newContents)
	analysis := pkgdiff.Analyze(relDiff)

	// Output.
	switch formatFlag {
	case "json":
		data, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(data))
	default:
		printDiffTable(analysis, packageName, oldVersion, newVersion)
	}

	// Threshold check.
	if threshold > 0 && float64(len(analysis.Findings)) >= threshold {
		return fmt.Errorf("%d finding(s) meet or exceed threshold %.0f",
			len(analysis.Findings), threshold)
	}

	return nil
}

func findPreviousVersion(sorted []string, target string) string {
	for i, v := range sorted {
		if v == target && i+1 < len(sorted) {
			return sorted[i+1]
		}
	}
	return ""
}

func defaultTarballURL(packageName, version string) string {
	return fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz",
		url.PathEscape(packageName), packageName, version)
}

func printDiffTable(analysis *pkgdiff.Analysis, pkg, oldVer, newVer string) {
	added, removed, modified := analysis.Diff.FileCount()

	_, _ = fmt.Fprintf(os.Stdout, "\n  Package: %s\n", pkg)
	_, _ = fmt.Fprintf(os.Stdout, "  Diff:    %s -> %s\n", oldVer, newVer)
	_, _ = fmt.Fprintf(os.Stdout, "  Files:   +%d -%d ~%d\n", added, removed, modified)

	if len(analysis.Findings) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "\n  No suspicious findings.")
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "\n  Code Analysis Findings (%d):\n", len(analysis.Findings))
		for _, f := range analysis.Findings {
			loc := ""
			if f.File != "" {
				loc = fmt.Sprintf(" (%s", f.File)
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d)", loc, f.Line)
				} else {
					loc += ")"
				}
			}
			_, _ = fmt.Fprintf(os.Stdout, "    [%-8s] %s%s\n", f.Severity, f.Message, loc)
		}
	}
	_, _ = fmt.Fprintln(os.Stdout)
}

// noopCache satisfies cache.Store for one-off diff operations where we don't
// want to persist anything to disk.
type noopCache struct{}

func (noopCache) Get(context.Context, string, string) ([]byte, error)                { return nil, nil }
func (noopCache) Set(context.Context, string, string, []byte, time.Duration) error    { return nil }
func (noopCache) Clear(context.Context) error                                         { return nil }
func (noopCache) Close() error                                                        { return nil }
