package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func testEvent() Event {
	return Event{
		Package:     "evil-pkg",
		Version:     "1.0.1",
		TargetScore: 72.5,
		Threshold:   50.0,
		RiskLevel:   "CRITICAL",
		Findings: []model.Finding{
			{Severity: model.SeverityCritical, Signal: "lifecycle_script", Message: "New postinstall script"},
			{Severity: model.SeverityHigh, Signal: "obfuscation", Message: "eval() usage detected"},
		},
	}
}

func TestWebhook_Success(t *testing.T) {
	var received Event

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL)
	event := testEvent()
	if err := wh.Notify(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.Package != "evil-pkg" {
		t.Errorf("expected package evil-pkg, got %s", received.Package)
	}
	if received.TargetScore != 72.5 {
		t.Errorf("expected score 72.5, got %.1f", received.TargetScore)
	}
}

func TestWebhook_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL)
	err := wh.Notify(context.Background(), testEvent())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestSlack_PayloadFormat(t *testing.T) {
	var payload slackPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSlack(srv.URL)
	event := testEvent()
	if err := s.Notify(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(payload.Text, "evil-pkg@1.0.1") {
		t.Errorf("fallback text should contain package info: %s", payload.Text)
	}
	if len(payload.Blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(payload.Blocks))
	}
	headerText := payload.Blocks[0].Text.Text
	if !strings.Contains(headerText, "evil-pkg@1.0.1") {
		t.Errorf("header should contain package: %s", headerText)
	}
	detailText := payload.Blocks[1].Text.Text
	if !strings.Contains(detailText, "72.5") {
		t.Errorf("detail should contain score: %s", detailText)
	}
	if !strings.Contains(detailText, "CRITICAL") {
		t.Errorf("detail should contain risk level: %s", detailText)
	}
}

func TestSlack_TruncatesFindings(t *testing.T) {
	var payload slackPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	event := testEvent()
	for i := 0; i < 8; i++ {
		event.Findings = append(event.Findings, model.Finding{
			Severity: model.SeverityMedium,
			Signal:   "test",
			Message:  "extra finding",
		})
	}
	// Now has 10 findings total

	s := NewSlack(srv.URL)
	if err := s.Notify(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	detailText := payload.Blocks[1].Text.Text
	if !strings.Contains(detailText, "and 5 more") {
		t.Errorf("should truncate findings with '... and N more': %s", detailText)
	}
}

func TestMulti_AllSucceed(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewMulti(NewWebhook(srv.URL), NewWebhook(srv.URL))
	if err := m.Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestMulti_PartialFailure(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	m := NewMulti(NewWebhook(good.URL), NewWebhook(bad.URL))
	err := m.Notify(context.Background(), testEvent())
	if err == nil {
		t.Fatal("expected error from partial failure")
	}
	// The good webhook should still have been called (fan-out continues on error).
	if !strings.Contains(err.Error(), "webhook") {
		t.Errorf("error should identify failing notifier: %v", err)
	}
}

func TestMulti_Empty(t *testing.T) {
	m := NewMulti()
	if err := m.Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("empty multi should succeed: %v", err)
	}
}

func TestWebhook_Name(t *testing.T) {
	w := NewWebhook("http://example.com")
	if w.Name() != "webhook" {
		t.Errorf("expected name 'webhook', got %q", w.Name())
	}
}

func TestSlack_Name(t *testing.T) {
	s := NewSlack("http://example.com")
	if s.Name() != "slack" {
		t.Errorf("expected name 'slack', got %q", s.Name())
	}
}
