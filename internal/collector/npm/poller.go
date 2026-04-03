package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/chainrecon/chainrecon/internal/collector"
)

// Poller checks for new versions of npm packages using conditional HTTP requests.
type Poller interface {
	// Poll checks whether a package has a new latest version since lastKnownVersion.
	// The etag is from the previous poll (empty for the first poll).
	Poll(ctx context.Context, packageName, lastKnownVersion, etag string) (PollResult, error)
}

// PollResult holds the outcome of a single poll.
type PollResult struct {
	PackageName   string
	LatestVersion string
	Changed       bool
	ETag          string
}

type poller struct {
	httpClient *http.Client
}

// NewPoller creates a new Poller that uses conditional HTTP requests with ETags.
func NewPoller() Poller {
	return &poller{
		httpClient: collector.NewHTTPClient(30 * time.Second),
	}
}

func (p *poller) Poll(ctx context.Context, packageName, lastKnownVersion, etag string) (PollResult, error) {
	reqURL := fmt.Sprintf("%s/%s", registryBaseURL, url.PathEscape(packageName))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("poll %s: create request: %w", packageName, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("poll %s: %w", packageName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	newETag := resp.Header.Get("ETag")

	if resp.StatusCode == http.StatusNotModified {
		return PollResult{
			PackageName:   packageName,
			LatestVersion: lastKnownVersion,
			Changed:       false,
			ETag:          newETag,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return PollResult{}, fmt.Errorf("poll %s: unexpected status %d", packageName, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return PollResult{}, fmt.Errorf("poll %s: read body: %w", packageName, err)
	}

	var partial struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return PollResult{}, fmt.Errorf("poll %s: parse response: %w", packageName, err)
	}

	latest := partial.DistTags["latest"]
	if latest == "" {
		return PollResult{}, fmt.Errorf("poll %s: no 'latest' dist-tag in response", packageName)
	}

	changed := lastKnownVersion != "" && latest != lastKnownVersion

	return PollResult{
		PackageName:   packageName,
		LatestVersion: latest,
		Changed:       changed,
		ETag:          newETag,
	}, nil
}
