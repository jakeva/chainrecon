package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/cache"
	"github.com/chainrecon/chainrecon/internal/model"
)

// newTestRegistryClient builds a registryClient pointed at the given test server.
func newTestRegistryClient(t *testing.T, server *httptest.Server) *registryClient {
	t.Helper()
	return &registryClient{
		httpClient: server.Client(),
		cache:      cache.NopStore{},
	}
}

func TestRegistryClient_FetchPackageMetadata(t *testing.T) {
	meta := model.PackageMetadata{
		Name: "express",
		DistTags: map[string]string{
			"latest": "4.18.2",
		},
		Versions: map[string]model.VersionDetail{
			"4.18.2": {Version: "4.18.2"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/express" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	// Point at the test server instead of the real npm registry.
	origURL := registryBaseURL
	registryBaseURL = server.URL
	defer func() { registryBaseURL = origURL }()

	got, err := rc.FetchPackageMetadata(context.Background(), "express")
	if err != nil {
		t.Fatalf("FetchPackageMetadata: %v", err)
	}
	if got.Name != "express" {
		t.Errorf("got name %q, want express", got.Name)
	}
	if got.DistTags["latest"] != "4.18.2" {
		t.Errorf("got latest %q, want 4.18.2", got.DistTags["latest"])
	}
}

func TestRegistryClient_FetchPackageMetadata_ScopedPackage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go's HTTP server decodes the path, so %40scope%2Fpkg arrives as @scope/sdk.
		// Check RawPath for the encoded form, or just match the decoded path.
		if r.URL.RawPath != "/%40anthropic-ai%2Fsdk" && r.URL.Path != "/@anthropic-ai/sdk" {
			t.Errorf("unexpected path: %s (raw: %s)", r.URL.Path, r.URL.RawPath)
			http.NotFound(w, r)
			return
		}
		meta := model.PackageMetadata{Name: "@anthropic-ai/sdk"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	origURL := registryBaseURL
	registryBaseURL = server.URL
	defer func() { registryBaseURL = origURL }()

	got, err := rc.FetchPackageMetadata(context.Background(), "@anthropic-ai/sdk")
	if err != nil {
		t.Fatalf("FetchPackageMetadata: %v", err)
	}
	if got.Name != "@anthropic-ai/sdk" {
		t.Errorf("got name %q, want @anthropic-ai/sdk", got.Name)
	}
}

func TestRegistryClient_FetchDownloadCounts(t *testing.T) {
	dl := model.DownloadCount{
		Downloads: 50000000,
		Package:   "lodash",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dl)
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	origURL := downloadsBaseURL
	downloadsBaseURL = server.URL
	defer func() { downloadsBaseURL = origURL }()

	got, err := rc.FetchDownloadCounts(context.Background(), "lodash")
	if err != nil {
		t.Fatalf("FetchDownloadCounts: %v", err)
	}
	if got.Downloads != 50000000 {
		t.Errorf("got %d downloads, want 50000000", got.Downloads)
	}
}

func TestRegistryClient_FetchDependentCount(t *testing.T) {
	result := model.SearchResult{Total: 12345}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	origURL := registryBaseURL
	registryBaseURL = server.URL
	defer func() { registryBaseURL = origURL }()

	got, err := rc.FetchDependentCount(context.Background(), "lodash")
	if err != nil {
		t.Fatalf("FetchDependentCount: %v", err)
	}
	if got != 12345 {
		t.Errorf("got %d dependents, want 12345", got)
	}
}

func TestRegistryClient_GetSortedVersions(t *testing.T) {
	rc := &registryClient{}
	now := time.Now()

	meta := &model.PackageMetadata{
		Versions: map[string]model.VersionDetail{
			"1.0.0": {Version: "1.0.0"},
			"2.0.0": {Version: "2.0.0"},
			"3.0.0": {Version: "3.0.0"},
			"4.0.0": {Version: "4.0.0"}, // no time entry, should be excluded
		},
		Time: map[string]time.Time{
			"1.0.0": now.Add(-3 * time.Hour),
			"2.0.0": now.Add(-1 * time.Hour),
			"3.0.0": now.Add(-2 * time.Hour),
		},
	}

	got := rc.GetSortedVersions(meta)
	if len(got) != 3 {
		t.Fatalf("got %d versions, want 3 (4.0.0 excluded)", len(got))
	}
	// Newest first: 2.0.0, 3.0.0, 1.0.0
	if got[0] != "2.0.0" || got[1] != "3.0.0" || got[2] != "1.0.0" {
		t.Errorf("unexpected sort order: %v", got)
	}
}

func TestRegistryClient_RetryOn429(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		dl := model.DownloadCount{Downloads: 999}
		_ = json.NewEncoder(w).Encode(dl)
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	origURL := downloadsBaseURL
	downloadsBaseURL = server.URL
	defer func() { downloadsBaseURL = origURL }()

	got, err := rc.FetchDownloadCounts(context.Background(), "test-pkg")
	if err != nil {
		t.Fatalf("FetchDownloadCounts after retries: %v", err)
	}
	if got.Downloads != 999 {
		t.Errorf("got %d downloads, want 999", got.Downloads)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRegistryClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	rc := newTestRegistryClient(t, server)
	origURL := registryBaseURL
	registryBaseURL = server.URL
	defer func() { registryBaseURL = origURL }()

	_, err := rc.FetchPackageMetadata(context.Background(), "express")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestRegistryClient_UserAgent(t *testing.T) {
	var gotUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		dl := model.DownloadCount{Downloads: 1}
		_ = json.NewEncoder(w).Encode(dl)
	}))
	defer server.Close()

	origUA := userAgent
	SetUserAgent("chainrecon/test")
	defer func() { userAgent = origUA }()

	rc := newTestRegistryClient(t, server)
	origURL := downloadsBaseURL
	downloadsBaseURL = server.URL
	defer func() { downloadsBaseURL = origURL }()

	_, _ = rc.FetchDownloadCounts(context.Background(), "test-pkg")
	if gotUA != "chainrecon/test" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "chainrecon/test")
	}
}
