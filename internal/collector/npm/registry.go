// Package npm provides an API client for the npm registry.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/chainrecon/chainrecon/internal/cache"
	"github.com/chainrecon/chainrecon/internal/collector"
	"github.com/chainrecon/chainrecon/internal/model"
)

var (
	registryBaseURL  = "https://registry.npmjs.org"
	downloadsBaseURL = "https://api.npmjs.org/downloads/point/last-week"
)

const (
	userAgentDefault = "chainrecon"

	metadataBucket   = "npm_metadata"
	downloadsBucket  = "npm_downloads"
	dependentsBucket = "npm_dependents"

	maxRetries        = 3
	initialBackoff    = 1 * time.Second
	backoffMultiplier = 2
)

var userAgent = userAgentDefault

// SetUserAgent overrides the default User-Agent header sent with all requests.
func SetUserAgent(ua string) {
	userAgent = ua
}

// RegistryClient defines the interface for interacting with the npm registry API.
type RegistryClient interface {
	// FetchPackageMetadata retrieves the full package metadata from the npm registry.
	FetchPackageMetadata(ctx context.Context, packageName string) (*model.PackageMetadata, error)

	// FetchDownloadCounts retrieves the last-week download counts for a package.
	FetchDownloadCounts(ctx context.Context, packageName string) (*model.DownloadCount, error)

	// FetchDependentCount returns the number of packages that depend on the given package.
	FetchDependentCount(ctx context.Context, packageName string) (int, error)

	// GetSortedVersions returns the version strings from metadata sorted by publish time, newest first.
	GetSortedVersions(metadata *model.PackageMetadata) []string
}

// registryClient is the concrete implementation of RegistryClient.
type registryClient struct {
	httpClient *http.Client
	cache      cache.Store
}

// NewRegistryClient creates a new RegistryClient backed by the given cache store.
func NewRegistryClient(c cache.Store) RegistryClient {
	return &registryClient{
		httpClient: collector.NewHTTPClient(30 * time.Second),
		cache:      c,
	}
}

// FetchPackageMetadata retrieves the full package metadata from the npm registry.
// Results are cached in the "npm_metadata" bucket with a 1-hour TTL.
func (r *registryClient) FetchPackageMetadata(ctx context.Context, packageName string) (*model.PackageMetadata, error) {
	cached, err := r.cache.Get(ctx, metadataBucket, packageName)
	if err != nil {
		return nil, fmt.Errorf("npm: cache get metadata for %q: %w", packageName, err)
	}
	if cached != nil {
		var meta model.PackageMetadata
		if err := json.Unmarshal(cached, &meta); err != nil {
			return nil, fmt.Errorf("npm: unmarshal cached metadata for %q: %w", packageName, err)
		}
		return &meta, nil
	}

	url := fmt.Sprintf("%s/%s", registryBaseURL, url.PathEscape(packageName))
	body, err := r.doRequestWithRetry(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch metadata for %q: %w", packageName, err)
	}

	var meta model.PackageMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("npm: unmarshal metadata for %q: %w", packageName, err)
	}

	if err := r.cache.Set(ctx, metadataBucket, packageName, body, cache.PackageMetadataTTL); err != nil {
		return nil, fmt.Errorf("npm: cache set metadata for %q: %w", packageName, err)
	}

	return &meta, nil
}

// FetchDownloadCounts retrieves the last-week download counts for a package.
// Results are cached in the "npm_downloads" bucket with a 6-hour TTL.
func (r *registryClient) FetchDownloadCounts(ctx context.Context, packageName string) (*model.DownloadCount, error) {
	cached, err := r.cache.Get(ctx, downloadsBucket, packageName)
	if err != nil {
		return nil, fmt.Errorf("npm: cache get downloads for %q: %w", packageName, err)
	}
	if cached != nil {
		var dl model.DownloadCount
		if err := json.Unmarshal(cached, &dl); err != nil {
			return nil, fmt.Errorf("npm: unmarshal cached downloads for %q: %w", packageName, err)
		}
		return &dl, nil
	}

	url := fmt.Sprintf("%s/%s", downloadsBaseURL, url.PathEscape(packageName))
	body, err := r.doRequestWithRetry(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch downloads for %q: %w", packageName, err)
	}

	var dl model.DownloadCount
	if err := json.Unmarshal(body, &dl); err != nil {
		return nil, fmt.Errorf("npm: unmarshal downloads for %q: %w", packageName, err)
	}

	if err := r.cache.Set(ctx, downloadsBucket, packageName, body, cache.DownloadCountTTL); err != nil {
		return nil, fmt.Errorf("npm: cache set downloads for %q: %w", packageName, err)
	}

	return &dl, nil
}

// FetchDependentCount returns the number of packages that depend on the given package.
// It queries the npm search API with a dependencies filter and returns the total count.
func (r *registryClient) FetchDependentCount(ctx context.Context, packageName string) (int, error) {
	cached, err := r.cache.Get(ctx, dependentsBucket, packageName)
	if err != nil {
		return 0, fmt.Errorf("npm: cache get dependent count for %q: %w", packageName, err)
	}
	if cached != nil {
		var result model.SearchResult
		if err := json.Unmarshal(cached, &result); err != nil {
			return 0, fmt.Errorf("npm: unmarshal cached dependent count for %q: %w", packageName, err)
		}
		return result.Total, nil
	}

	url := fmt.Sprintf("%s/-/v1/search?text=dependencies:%s&size=1", registryBaseURL, url.QueryEscape(packageName))
	body, err := r.doRequestWithRetry(ctx, url)
	if err != nil {
		return 0, fmt.Errorf("npm: fetch dependent count for %q: %w", packageName, err)
	}

	var result model.SearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("npm: unmarshal dependent count for %q: %w", packageName, err)
	}

	if err := r.cache.Set(ctx, dependentsBucket, packageName, body, cache.PackageMetadataTTL); err != nil {
		return 0, fmt.Errorf("npm: cache set dependent count for %q: %w", packageName, err)
	}

	return result.Total, nil
}

// GetSortedVersions returns the version strings from the given metadata sorted
// by publish time in descending order (newest first). Versions without a recorded
// publish time are excluded.
func (r *registryClient) GetSortedVersions(metadata *model.PackageMetadata) []string {
	versions := make([]string, 0, len(metadata.Versions))
	for v := range metadata.Versions {
		if _, ok := metadata.Time[v]; ok {
			versions = append(versions, v)
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		return metadata.Time[versions[i]].After(metadata.Time[versions[j]])
	})

	return versions
}

// doRequestWithRetry performs an HTTP GET with exponential backoff on 429 responses.
// It retries up to maxRetries times, respecting any Retry-After header.
func (r *registryClient) doRequestWithRetry(ctx context.Context, url string) ([]byte, error) {
	backoff := initialBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")

		resp, err := r.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("execute request: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			_ = resp.Body.Close()

			wait := backoff
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, err := strconv.Atoi(ra); err == nil {
					wait = time.Duration(seconds) * time.Second
				}
			}

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
			case <-time.After(wait):
			}

			backoff *= backoffMultiplier
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d for %s: %s", resp.StatusCode, url, string(body))
		}

		return body, nil
	}

	return nil, fmt.Errorf("max retries exceeded for %s", url)
}
