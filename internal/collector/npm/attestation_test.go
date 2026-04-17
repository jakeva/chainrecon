package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jakeva/chainrecon/internal/cache"
	"github.com/jakeva/chainrecon/internal/model"
)

func newTestAttestationClient(t *testing.T, server *httptest.Server) *attestationClient {
	t.Helper()
	return &attestationClient{
		httpClient: server.Client(),
		cache:      cache.NopStore{},
	}
}

func TestAttestationClient_FetchAttestations(t *testing.T) {
	bundle := model.AttestationBundle{
		Attestations: []model.Attestation{
			{PredicateType: "https://slsa.dev/provenance/v1"},
			{PredicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	ac := newTestAttestationClient(t, server)
	origURL := attestationBaseURL
	attestationBaseURL = server.URL
	defer func() { attestationBaseURL = origURL }()

	got, err := ac.FetchAttestations(context.Background(), "express", "4.18.2")
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(got.Attestations) != 2 {
		t.Fatalf("got %d attestations, want 2", len(got.Attestations))
	}
}

func TestAttestationClient_FetchAttestations_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ac := newTestAttestationClient(t, server)
	origURL := attestationBaseURL
	attestationBaseURL = server.URL
	defer func() { attestationBaseURL = origURL }()

	got, err := ac.FetchAttestations(context.Background(), "old-package", "0.1.0")
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(got.Attestations) != 0 {
		t.Errorf("expected empty bundle for 404, got %d attestations", len(got.Attestations))
	}
}

func TestAttestationClient_FetchVersionAttestations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundle := model.AttestationBundle{
			Attestations: []model.Attestation{
				{PredicateType: "https://slsa.dev/provenance/v1"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	ac := newTestAttestationClient(t, server)
	origURL := attestationBaseURL
	attestationBaseURL = server.URL
	defer func() { attestationBaseURL = origURL }()

	versions := []string{"1.0.0", "1.0.1", "2.0.0"}
	got, err := ac.FetchVersionAttestations(context.Background(), "test-pkg", versions)
	if err != nil {
		t.Fatalf("FetchVersionAttestations: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	for _, va := range got {
		if !va.HasSLSA {
			t.Errorf("version %s: expected HasSLSA=true", va.Version)
		}
	}
}

func TestClassifyBundle_SLSAOnly(t *testing.T) {
	bundle := &model.AttestationBundle{
		Attestations: []model.Attestation{
			{PredicateType: "https://slsa.dev/provenance/v1"},
		},
	}
	va := classifyBundle("1.0.0", bundle)
	if !va.HasSLSA {
		t.Error("expected HasSLSA=true")
	}
	if va.HasPublish {
		t.Error("expected HasPublish=false")
	}
	if !va.HasAnyProvenance {
		t.Error("expected HasAnyProvenance=true")
	}
}

func TestClassifyBundle_PublishOnly(t *testing.T) {
	bundle := &model.AttestationBundle{
		Attestations: []model.Attestation{
			{PredicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"},
		},
	}
	va := classifyBundle("1.0.0", bundle)
	if va.HasSLSA {
		t.Error("expected HasSLSA=false")
	}
	if !va.HasPublish {
		t.Error("expected HasPublish=true")
	}
	if !va.HasAnyProvenance {
		t.Error("expected HasAnyProvenance=true")
	}
}

func TestClassifyBundle_Empty(t *testing.T) {
	bundle := &model.AttestationBundle{}
	va := classifyBundle("1.0.0", bundle)
	if va.HasSLSA || va.HasPublish || va.HasAnyProvenance {
		t.Error("expected all false for empty bundle")
	}
}
