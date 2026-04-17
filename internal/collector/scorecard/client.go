// Package scorecard provides a client for the OpenSSF Scorecard API.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jakeva/chainrecon/internal/cache"
	"github.com/jakeva/chainrecon/internal/collector"
	"github.com/jakeva/chainrecon/internal/model"
)

var baseURL = "https://api.scorecard.dev/projects"

const (
	cacheBucket = "scorecard"
	cacheTTL    = 24 * time.Hour
)

// Client defines the interface for querying the OpenSSF Scorecard API.
type Client interface {
	// FetchScore retrieves the Scorecard result for a GitHub repository.
	// Returns nil (not an error) if the repository has not been scored.
	FetchScore(ctx context.Context, owner, repo string) (*model.ScorecardResult, error)
}

type client struct {
	httpClient *http.Client
	cache      cache.Store
}

// NewClient creates a new Scorecard API client.
func NewClient(c cache.Store) Client {
	return &client{
		httpClient: collector.NewHTTPClient(15 * time.Second),
		cache:      c,
	}
}

// FetchScore retrieves the Scorecard result for a GitHub repository.
// Returns nil if the repo has not been scored yet (404).
func (c *client) FetchScore(ctx context.Context, owner, repo string) (*model.ScorecardResult, error) {
	cacheKey := owner + "/" + repo

	cached, err := c.cache.Get(ctx, cacheBucket, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("scorecard: cache get %q: %w", cacheKey, err)
	}
	if cached != nil {
		// A cached empty object means "not scored" from a previous lookup.
		if string(cached) == "null" {
			return nil, nil
		}
		var result model.ScorecardResult
		if err := json.Unmarshal(cached, &result); err != nil {
			return nil, fmt.Errorf("scorecard: unmarshal cached %q: %w", cacheKey, err)
		}
		return &result, nil
	}

	reqURL := fmt.Sprintf("%s/github.com/%s/%s", baseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("scorecard: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scorecard: execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("scorecard: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// Cache the miss so we don't keep hitting the API.
		_ = c.cache.Set(ctx, cacheBucket, cacheKey, []byte("null"), cacheTTL)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard: unexpected status %d for %s: %s", resp.StatusCode, cacheKey, string(body))
	}

	var result model.ScorecardResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("scorecard: decode %q: %w", cacheKey, err)
	}

	if err := c.cache.Set(ctx, cacheBucket, cacheKey, body, cacheTTL); err != nil {
		return nil, fmt.Errorf("scorecard: cache set %q: %w", cacheKey, err)
	}

	return &result, nil
}
