// Package npm provides clients for the npm registry APIs.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/jakeva/chainrecon/internal/cache"
	"github.com/jakeva/chainrecon/internal/collector"
	"github.com/jakeva/chainrecon/internal/model"
)

var attestationBaseURL = "https://registry.npmjs.org/-/npm/v1/attestations"

const attestationCacheBucket = "npm_attestations"

// AttestationClient defines the interface for fetching npm attestation data.
type AttestationClient interface {
	// FetchAttestations retrieves the attestation bundle for a specific package version
	// from the npm registry.
	FetchAttestations(ctx context.Context, packageName, version string) (*model.AttestationBundle, error)

	// FetchVersionAttestations retrieves attestation summaries for multiple versions
	// of a package, returning the provenance state of each.
	FetchVersionAttestations(ctx context.Context, packageName string, versions []string) ([]model.VersionAttestation, error)
}

type attestationClient struct {
	cache      cache.Store
	httpClient *http.Client
}

// NewAttestationClient creates a new AttestationClient backed by the given cache store.
func NewAttestationClient(c cache.Store) AttestationClient {
	return &attestationClient{
		cache:      c,
		httpClient: collector.NewHTTPClient(30 * time.Second),
	}
}

// FetchAttestations retrieves the attestation bundle for a specific package version.
// It returns an empty bundle (not an error) when the registry returns 404,
// indicating the package or version has no attestations.
func (c *attestationClient) FetchAttestations(ctx context.Context, packageName, version string) (*model.AttestationBundle, error) {
	cacheKey := packageName + "@" + version

	// Check cache first.
	cached, err := c.cache.Get(ctx, attestationCacheBucket, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("npm attestations: cache get %q: %w", cacheKey, err)
	}
	if cached != nil {
		var bundle model.AttestationBundle
		if err := json.Unmarshal(cached, &bundle); err != nil {
			return nil, fmt.Errorf("npm attestations: unmarshal cached %q: %w", cacheKey, err)
		}
		return &bundle, nil
	}

	// Build request URL with properly encoded package name for scoped packages.
	encodedPkg := url.PathEscape(packageName)
	reqURL := fmt.Sprintf("%s/%s@%s", attestationBaseURL, encodedPkg, version)

	body, err := c.doRequestWithRetry(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("npm attestations: fetch %q: %w", cacheKey, err)
	}

	// A nil body signals a 404 — package/version has no attestations.
	if body == nil {
		empty := &model.AttestationBundle{}
		if err := c.cacheBundle(ctx, cacheKey, empty); err != nil {
			return nil, err
		}
		return empty, nil
	}

	var bundle model.AttestationBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, fmt.Errorf("npm attestations: decode %q: %w", cacheKey, err)
	}

	if err := c.cacheBundle(ctx, cacheKey, &bundle); err != nil {
		return nil, err
	}

	return &bundle, nil
}

// FetchVersionAttestations retrieves attestation summaries for multiple versions of a package.
// Each returned VersionAttestation indicates whether SLSA provenance and/or a publish
// attestation were found for that version.
func (c *attestationClient) FetchVersionAttestations(ctx context.Context, packageName string, versions []string) ([]model.VersionAttestation, error) {
	results := make([]model.VersionAttestation, len(versions))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5) // cap concurrency to avoid hammering the registry

	for i, ver := range versions {
		g.Go(func() error {
			bundle, err := c.FetchAttestations(ctx, packageName, ver)
			if err != nil {
				return fmt.Errorf("npm attestations: version %s: %w", ver, err)
			}
			results[i] = classifyBundle(ver, bundle)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// doRequestWithRetry performs an HTTP GET with exponential backoff on 429 responses.
// It returns nil body (not an error) on 404.
func (c *attestationClient) doRequestWithRetry(ctx context.Context, reqURL string) ([]byte, error) {
	var lastErr error
	backoff := initialBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("execute request: %w", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr != nil {
			return nil, fmt.Errorf("read response body: %w", readErr)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusNotFound:
			return nil, nil
		case http.StatusTooManyRequests:
			lastErr = fmt.Errorf("rate limited (HTTP 429), attempt %d/%d", attempt+1, maxRetries+1)
			continue
		default:
			return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// cacheBundle serialises and stores an attestation bundle in the cache.
func (c *attestationClient) cacheBundle(ctx context.Context, key string, bundle *model.AttestationBundle) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("npm attestations: marshal for cache %q: %w", key, err)
	}
	if err := c.cache.Set(ctx, attestationCacheBucket, key, data, cache.AttestationDataTTL); err != nil {
		return fmt.Errorf("npm attestations: cache set %q: %w", key, err)
	}
	return nil
}

// classifyBundle inspects an AttestationBundle and returns a VersionAttestation
// summarising which provenance types are present.
func classifyBundle(version string, bundle *model.AttestationBundle) model.VersionAttestation {
	va := model.VersionAttestation{Version: version}

	for _, att := range bundle.Attestations {
		if strings.HasPrefix(att.PredicateType, "https://slsa.dev/provenance") {
			va.HasSLSA = true
		}
		if strings.HasPrefix(att.PredicateType, "https://github.com/npm/attestation/tree/main/specs/publish") {
			va.HasPublish = true
		}
	}

	va.HasAnyProvenance = va.HasSLSA || va.HasPublish
	return va
}
