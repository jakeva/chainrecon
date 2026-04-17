package watch

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/jakeva/chainrecon/internal/cache"
	"github.com/jakeva/chainrecon/internal/collector/npm"
	pkgdiff "github.com/jakeva/chainrecon/internal/diff"
	"github.com/jakeva/chainrecon/internal/model"
)

// DefaultDiffFunc returns a DiffFunc that downloads tarballs and runs the
// full code analysis pipeline. It creates a fresh registry client per call
// with no caching since diff operations are one-off.
func DefaultDiffFunc() DiffFunc {
	return func(ctx context.Context, packageName, oldVersion, newVersion string) ([]model.CodeFinding, error) {
		registry := npm.NewRegistryClient(nopCache{})
		meta, err := registry.FetchPackageMetadata(ctx, packageName)
		if err != nil {
			return nil, fmt.Errorf("fetch metadata: %w", err)
		}

		oldURL := tarballURL(meta, packageName, oldVersion)
		newURL := tarballURL(meta, packageName, newVersion)

		tc := npm.NewTarballClient()

		oldContents, err := tc.FetchContents(ctx, packageName, oldVersion, oldURL)
		if err != nil {
			return nil, fmt.Errorf("fetch old tarball: %w", err)
		}

		newContents, err := tc.FetchContents(ctx, packageName, newVersion, newURL)
		if err != nil {
			return nil, fmt.Errorf("fetch new tarball: %w", err)
		}

		relDiff := pkgdiff.Compare(oldContents, newContents)
		analysis := pkgdiff.Analyze(relDiff)
		return analysis.Findings, nil
	}
}

func tarballURL(meta *model.PackageMetadata, packageName, version string) string {
	if detail, ok := meta.Versions[version]; ok && detail.Dist.Tarball != "" {
		return detail.Dist.Tarball
	}
	return fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz",
		url.PathEscape(packageName), packageName, version)
}

// nopCache satisfies cache.Store for one-off operations.
type nopCache struct{}

func (nopCache) Get(context.Context, string, string) ([]byte, error)             { return nil, nil }
func (nopCache) Set(context.Context, string, string, []byte, time.Duration) error { return nil }
func (nopCache) Clear(context.Context) error                                      { return nil }
func (nopCache) Close() error                                                     { return nil }

// Verify nopCache implements cache.Store at compile time.
var _ cache.Store = nopCache{}
