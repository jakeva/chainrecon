package scorecard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestFetchScore_Success(t *testing.T) {
	result := model.ScorecardResult{
		Score: 7.5,
		Checks: []model.ScorecardCheck{
			{Name: "Branch-Protection", Score: 8, Reason: "branch protection enabled"},
			{Name: "Dangerous-Workflow", Score: 10, Reason: "no dangerous workflows"},
		},
	}
	body, _ := json.Marshal(result)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/github.com/expressjs/express" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL + "/projects"
	defer func() { baseURL = old }()

	c := NewClient(nopCache{})
	got, err := c.FetchScore(context.Background(), "expressjs", "express")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Score != 7.5 {
		t.Errorf("Score = %.1f, want 7.5", got.Score)
	}
	if len(got.Checks) != 2 {
		t.Errorf("got %d checks, want 2", len(got.Checks))
	}
}

func TestFetchScore_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL + "/projects"
	defer func() { baseURL = old }()

	c := NewClient(nopCache{})
	got, err := c.FetchScore(context.Background(), "nobody", "nothing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for 404, got score %.1f", got.Score)
	}
}

func TestFetchScore_CachedNull(t *testing.T) {
	// A previous 404 stores "null" in the cache. Verify it returns nil
	// without hitting the server.
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL + "/projects"
	defer func() { baseURL = old }()

	store := &memCache{data: map[string][]byte{
		"scorecard:foo/bar": []byte("null"),
	}}

	c := NewClient(store)
	got, err := c.FetchScore(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil for cached null")
	}
	if requestCount != 0 {
		t.Errorf("expected 0 HTTP requests for cached null, got %d", requestCount)
	}
}

func TestFetchScore_CachedResult(t *testing.T) {
	result := model.ScorecardResult{Score: 9.0}
	body, _ := json.Marshal(result)

	store := &memCache{data: map[string][]byte{
		"scorecard:foo/bar": body,
	}}

	c := NewClient(store)
	got, err := c.FetchScore(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Score != 9.0 {
		t.Errorf("expected cached score 9.0, got %v", got)
	}
}

func TestFetchScore_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL + "/projects"
	defer func() { baseURL = old }()

	c := NewClient(nopCache{})
	_, err := c.FetchScore(context.Background(), "foo", "bar")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// nopCache is a no-op cache for testing.
type nopCache struct{}

func (nopCache) Get(_ context.Context, _, _ string) ([]byte, error)                 { return nil, nil }
func (nopCache) Set(_ context.Context, _, _ string, _ []byte, _ time.Duration) error { return nil }
func (nopCache) Clear(_ context.Context) error                                       { return nil }
func (nopCache) Close() error                                                        { return nil }

// memCache is a simple in-memory cache for testing cached lookups.
type memCache struct {
	data map[string][]byte
}

func (m *memCache) Get(_ context.Context, bucket, key string) ([]byte, error) {
	return m.data[bucket+":"+key], nil
}
func (m *memCache) Set(_ context.Context, _, _ string, _ []byte, _ time.Duration) error { return nil }
func (m *memCache) Clear(_ context.Context) error                                       { return nil }
func (m *memCache) Close() error                                                        { return nil }
