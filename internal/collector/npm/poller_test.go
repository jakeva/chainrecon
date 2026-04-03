package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPoller_FirstPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.2.3"}}`))
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	result, err := p.Poll(context.Background(), "test-pkg", "", "")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if result.LatestVersion != "1.2.3" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "1.2.3")
	}
	if result.Changed {
		t.Error("Changed should be false on first poll (no lastKnownVersion)")
	}
	if result.ETag != `"abc123"` {
		t.Errorf("ETag = %q, want %q", result.ETag, `"abc123"`)
	}
}

func TestPoller_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Error("expected If-None-Match header")
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	result, err := p.Poll(context.Background(), "test-pkg", "1.2.3", `"abc123"`)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if result.Changed {
		t.Error("Changed should be false on 304")
	}
	if result.LatestVersion != "1.2.3" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "1.2.3")
	}
}

func TestPoller_VersionChanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"def456"`)
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.3.0"}}`))
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	result, err := p.Poll(context.Background(), "test-pkg", "1.2.3", `"abc123"`)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if !result.Changed {
		t.Error("Changed should be true when version differs")
	}
	if result.LatestVersion != "1.3.0" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "1.3.0")
	}
	if result.ETag != `"def456"` {
		t.Errorf("ETag = %q, want %q", result.ETag, `"def456"`)
	}
}

func TestPoller_SameVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"def456"`)
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.2.3"}}`))
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	result, err := p.Poll(context.Background(), "test-pkg", "1.2.3", `"abc123"`)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if result.Changed {
		t.Error("Changed should be false when version is the same")
	}
}

func TestPoller_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	_, err := p.Poll(context.Background(), "test-pkg", "1.2.3", "")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestPoller_NoLatestDistTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dist-tags":{}}`))
	}))
	defer srv.Close()

	old := registryBaseURL
	registryBaseURL = srv.URL
	defer func() { registryBaseURL = old }()

	p := NewPoller()
	_, err := p.Poll(context.Background(), "test-pkg", "1.2.3", "")
	if err == nil {
		t.Fatal("expected error when no latest dist-tag")
	}
}
