// Package github provides a client for the GitHub API, focused on
// release and tag data for npm version correlation.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/chainrecon/chainrecon/internal/cache"
	"github.com/chainrecon/chainrecon/internal/model"
)

var apiBaseURL = "https://api.github.com"

const (
	cacheBucket = "github_releases"
	cacheTTL    = 1 * time.Hour
)

// Client defines the interface for querying GitHub release and tag data.
type Client interface {
	// FetchReleases retrieves the releases for a GitHub repository.
	// Returns an empty slice (not an error) if the repo has no releases.
	FetchReleases(ctx context.Context, owner, repo string) ([]model.GitHubRelease, error)

	// FetchTags retrieves the git tags for a GitHub repository.
	// Returns an empty slice (not an error) if the repo has no tags.
	FetchTags(ctx context.Context, owner, repo string) ([]model.GitHubTag, error)
}

type client struct {
	httpClient *http.Client
	cache      cache.Store
	token      string
}

// NewClient creates a new GitHub API client. If token is non-empty, it is
// used for authentication (increasing the rate limit from 60 to 5000 req/hr).
func NewClient(c cache.Store, token string) Client {
	return &client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      c,
		token:      token,
	}
}

// FetchReleases retrieves up to 100 releases for a GitHub repository.
func (c *client) FetchReleases(ctx context.Context, owner, repo string) ([]model.GitHubRelease, error) {
	cacheKey := owner + "/" + repo

	cached, err := c.cache.Get(ctx, cacheBucket, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("github: cache get %q: %w", cacheKey, err)
	}
	if cached != nil {
		var releases []model.GitHubRelease
		if err := json.Unmarshal(cached, &releases); err != nil {
			return nil, fmt.Errorf("github: unmarshal cached %q: %w", cacheKey, err)
		}
		return releases, nil
	}

	reqURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100",
		apiBaseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unexpected status %d for %s: %s", resp.StatusCode, cacheKey, string(body))
	}

	var releases []model.GitHubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("github: decode %q: %w", cacheKey, err)
	}

	if err := c.cache.Set(ctx, cacheBucket, cacheKey, body, cacheTTL); err != nil {
		return nil, fmt.Errorf("github: cache set %q: %w", cacheKey, err)
	}

	return releases, nil
}

const tagCacheBucket = "github_tags"

// FetchTags retrieves up to 100 git tags for a GitHub repository.
func (c *client) FetchTags(ctx context.Context, owner, repo string) ([]model.GitHubTag, error) {
	cacheKey := owner + "/" + repo

	cached, err := c.cache.Get(ctx, tagCacheBucket, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("github: cache get tags %q: %w", cacheKey, err)
	}
	if cached != nil {
		var tags []model.GitHubTag
		if err := json.Unmarshal(cached, &tags); err != nil {
			return nil, fmt.Errorf("github: unmarshal cached tags %q: %w", cacheKey, err)
		}
		return tags, nil
	}

	reqURL := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=100",
		apiBaseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unexpected status %d for tags %s: %s", resp.StatusCode, cacheKey, string(body))
	}

	var tags []model.GitHubTag
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("github: decode tags %q: %w", cacheKey, err)
	}

	if err := c.cache.Set(ctx, tagCacheBucket, cacheKey, body, cacheTTL); err != nil {
		return nil, fmt.Errorf("github: cache set tags %q: %w", cacheKey, err)
	}

	return tags, nil
}
