package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchReleases_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/axios/axios/releases" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"tag_name":"v1.7.2","name":"v1.7.2"},{"tag_name":"v1.7.1","name":"v1.7.1"}]`))
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "")
	releases, err := c.FetchReleases(context.Background(), "axios", "axios")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(releases) != 2 {
		t.Fatalf("got %d releases, want 2", len(releases))
	}
	if releases[0].TagName != "v1.7.2" {
		t.Errorf("releases[0].TagName = %q, want %q", releases[0].TagName, "v1.7.2")
	}
}

func TestFetchReleases_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "")
	releases, err := c.FetchReleases(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if releases != nil {
		t.Errorf("expected nil releases for 404, got %d", len(releases))
	}
}

func TestFetchReleases_WithToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "ghp_testtoken123")
	_, err := c.FetchReleases(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer ghp_testtoken123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer ghp_testtoken123")
	}
}

func TestFetchReleases_Pagination(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		page := r.URL.Query().Get("page")

		w.Header().Set("Content-Type", "application/json")

		switch page {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next"`, "http://"+r.Host, r.URL.Path))
			_, _ = w.Write([]byte(`[{"tag_name":"v3.0.0"},{"tag_name":"v2.0.0"}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"tag_name":"v1.0.0"}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "")
	releases, err := c.FetchReleases(context.Background(), "big", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(releases) != 3 {
		t.Fatalf("got %d releases, want 3 (across 2 pages)", len(releases))
	}
	if requestCount != 2 {
		t.Errorf("made %d requests, want 2", requestCount)
	}
}

func TestFetchTags_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/express/express/tags" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"v5.0.0"},{"name":"v4.21.2"},{"name":"v4.21.1"}]`))
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "")
	tags, err := c.FetchTags(context.Background(), "express", "express")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tags) != 3 {
		t.Fatalf("got %d tags, want 3", len(tags))
	}
	if tags[0].Name != "v5.0.0" {
		t.Errorf("tags[0].Name = %q, want %q", tags[0].Name, "v5.0.0")
	}
}

func TestFetchTags_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	c := NewClient(nopCache{}, "")
	tags, err := c.FetchTags(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tags != nil {
		t.Errorf("expected nil tags for 404, got %d", len(tags))
	}
}

func TestParseNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "with next",
			header: `<https://api.github.com/repos/foo/bar/releases?page=2>; rel="next", <https://api.github.com/repos/foo/bar/releases?page=5>; rel="last"`,
			want:   "https://api.github.com/repos/foo/bar/releases?page=2",
		},
		{
			name:   "no next",
			header: `<https://api.github.com/repos/foo/bar/releases?page=1>; rel="prev"`,
			want:   "",
		},
		{
			name:   "empty",
			header: "",
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNextLink(tc.header)
			if got != tc.want {
				t.Errorf("parseNextLink() = %q, want %q", got, tc.want)
			}
		})
	}
}

// nopCache is a no-op cache for testing.
type nopCache struct{}

func (nopCache) Get(_ context.Context, _, _ string) ([]byte, error)                 { return nil, nil }
func (nopCache) Set(_ context.Context, _, _ string, _ []byte, _ time.Duration) error { return nil }
func (nopCache) Clear(_ context.Context) error                                       { return nil }
func (nopCache) Close() error                                                        { return nil }
