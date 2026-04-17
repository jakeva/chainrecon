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
	"regexp"
	"time"

	"github.com/jakeva/chainrecon/internal/cache"
	"github.com/jakeva/chainrecon/internal/collector"
	"github.com/jakeva/chainrecon/internal/model"
)

var apiBaseURL = "https://api.github.com"

const (
	cacheTTL = 1 * time.Hour
	maxPages = 3 // fetch up to 300 items per resource
)

// Client defines the interface for querying GitHub release and tag data.
type Client interface {
	// FetchReleases retrieves the releases for a GitHub repository.
	// Returns nil (not an error) if the repo is not found.
	FetchReleases(ctx context.Context, owner, repo string) ([]model.GitHubRelease, error)

	// FetchTags retrieves the git tags for a GitHub repository.
	// Returns nil (not an error) if the repo is not found.
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
		httpClient: collector.NewHTTPClient(15 * time.Second),
		cache:      c,
		token:      token,
	}
}

// FetchReleases retrieves releases for a GitHub repository, paginating
// up to maxPages pages of 100 results each.
func (c *client) FetchReleases(ctx context.Context, owner, repo string) ([]model.GitHubRelease, error) {
	cacheKey := owner + "/" + repo
	const bucket = "github_releases"

	cached, err := c.cache.Get(ctx, bucket, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("github: cache get releases %q: %w", cacheKey, err)
	}
	if cached != nil {
		var releases []model.GitHubRelease
		if err := json.Unmarshal(cached, &releases); err != nil {
			return nil, fmt.Errorf("github: unmarshal cached releases %q: %w", cacheKey, err)
		}
		return releases, nil
	}

	startURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100",
		apiBaseURL, url.PathEscape(owner), url.PathEscape(repo))

	raw, err := c.fetchPaginated(ctx, startURL, cacheKey)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	var releases []model.GitHubRelease
	if err := json.Unmarshal(raw, &releases); err != nil {
		return nil, fmt.Errorf("github: decode releases %q: %w", cacheKey, err)
	}

	if err := c.cache.Set(ctx, bucket, cacheKey, raw, cacheTTL); err != nil {
		return nil, fmt.Errorf("github: cache set releases %q: %w", cacheKey, err)
	}

	return releases, nil
}

// FetchTags retrieves git tags for a GitHub repository, paginating
// up to maxPages pages of 100 results each.
func (c *client) FetchTags(ctx context.Context, owner, repo string) ([]model.GitHubTag, error) {
	cacheKey := owner + "/" + repo
	const bucket = "github_tags"

	cached, err := c.cache.Get(ctx, bucket, cacheKey)
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

	startURL := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=100",
		apiBaseURL, url.PathEscape(owner), url.PathEscape(repo))

	raw, err := c.fetchPaginated(ctx, startURL, cacheKey)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	var tags []model.GitHubTag
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, fmt.Errorf("github: decode tags %q: %w", cacheKey, err)
	}

	if err := c.cache.Set(ctx, bucket, cacheKey, raw, cacheTTL); err != nil {
		return nil, fmt.Errorf("github: cache set tags %q: %w", cacheKey, err)
	}

	return tags, nil
}

// fetchPaginated fetches JSON arrays from the GitHub API, following Link
// rel="next" headers up to maxPages. Returns the merged JSON array as raw
// bytes, or nil for 404 responses.
func (c *client) fetchPaginated(ctx context.Context, startURL, label string) ([]byte, error) {
	var all []json.RawMessage
	nextURL := startURL

	for page := 0; page < maxPages && nextURL != ""; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("github: create request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: request %q: %w", label, err)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("github: read response %q: %w", label, err)
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github: status %d for %s: %s", resp.StatusCode, label, string(body))
		}

		var pageItems []json.RawMessage
		if err := json.Unmarshal(body, &pageItems); err != nil {
			return nil, fmt.Errorf("github: decode page %q: %w", label, err)
		}
		all = append(all, pageItems...)

		nextURL = parseNextLink(resp.Header.Get("Link"))
	}

	if len(all) == 0 {
		return []byte("[]"), nil
	}

	return json.Marshal(all)
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseNextLink extracts the "next" URL from a GitHub Link header.
func parseNextLink(header string) string {
	if header == "" {
		return ""
	}
	m := linkNextRe.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
