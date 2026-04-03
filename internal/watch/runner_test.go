package watch

import (
	"context"
	"testing"
	"time"

	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/model"
	"github.com/chainrecon/chainrecon/internal/state"
	"github.com/chainrecon/chainrecon/internal/watchlist"
)

type fakePoller struct {
	results map[string]npm.PollResult
	err     error
}

func (f *fakePoller) Poll(_ context.Context, pkg, _, _ string) (npm.PollResult, error) {
	if f.err != nil {
		return npm.PollResult{}, f.err
	}
	r, ok := f.results[pkg]
	if !ok {
		return npm.PollResult{PackageName: pkg, LatestVersion: "1.0.0"}, nil
	}
	return r, nil
}

func fakeScanFunc(score float64) ScanFunc {
	return func(_ context.Context, pkg, version string) (*model.Report, error) {
		return &model.Report{
			Package: pkg,
			Version: version,
			Scores:  model.Scores{TargetScore: score},
		}, nil
	}
}

func TestRunOnce_NoAlerts(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 70.0},
		Packages: []watchlist.Entry{
			{Name: "express"},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"express": {PackageName: "express", LatestVersion: "4.18.2", Changed: true, ETag: `"e1"`},
		},
	}

	runner := NewRunner(wl, poller, fakeScanFunc(30.0), state.New(), nil)

	alerts, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}

	// Verify state was updated.
	ps, ok := runner.State().Packages["express"]
	if !ok {
		t.Fatal("expected express in state")
	}
	if ps.LastScannedVersion != "4.18.2" {
		t.Errorf("LastScannedVersion = %q, want %q", ps.LastScannedVersion, "4.18.2")
	}
}

func TestRunOnce_WithAlert(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 50.0},
		Packages: []watchlist.Entry{
			{Name: "risky-pkg"},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"risky-pkg": {PackageName: "risky-pkg", LatestVersion: "2.0.0", Changed: true, ETag: `"r1"`},
		},
	}

	runner := NewRunner(wl, poller, fakeScanFunc(75.0), state.New(), nil)

	alerts, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Package != "risky-pkg" {
		t.Errorf("alert package = %q, want %q", alerts[0].Package, "risky-pkg")
	}
	if alerts[0].TargetScore != 75.0 {
		t.Errorf("alert score = %f, want 75.0", alerts[0].TargetScore)
	}
}

func TestRunOnce_SkipsUnchanged(t *testing.T) {
	wl := &watchlist.Watchlist{
		Packages: []watchlist.Entry{
			{Name: "stable-pkg"},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"stable-pkg": {PackageName: "stable-pkg", LatestVersion: "1.0.0", Changed: false, ETag: `"s1"`},
		},
	}

	scanCalled := false
	scanFn := func(_ context.Context, _, _ string) (*model.Report, error) {
		scanCalled = true
		return &model.Report{Scores: model.Scores{TargetScore: 10.0}}, nil
	}

	// Pre-populate state so the skip logic triggers.
	st := state.New()
	st.Update("stable-pkg", "1.0.0", 10.0, "LOW", `"s0"`)

	runner := NewRunner(wl, poller, scanFn, st, nil)

	_, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if scanCalled {
		t.Error("scan should not be called when version is unchanged")
	}
}

func TestRunOnce_EntryThresholdOverride(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 90.0},
		Packages: []watchlist.Entry{
			{Name: "strict-pkg", Threshold: 30.0},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"strict-pkg": {PackageName: "strict-pkg", LatestVersion: "1.0.0", Changed: true},
		},
	}

	runner := NewRunner(wl, poller, fakeScanFunc(50.0), state.New(), nil)

	alerts, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert (entry threshold 30 < score 50), got %d", len(alerts))
	}
	if alerts[0].Threshold != 30.0 {
		t.Errorf("alert threshold = %f, want 30.0", alerts[0].Threshold)
	}
}

func TestRunOnce_MultiplePackages(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 50.0},
		Packages: []watchlist.Entry{
			{Name: "pkg-a"},
			{Name: "pkg-b"},
			{Name: "pkg-c"},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"pkg-a": {PackageName: "pkg-a", LatestVersion: "1.0.0", Changed: true},
			"pkg-b": {PackageName: "pkg-b", LatestVersion: "2.0.0", Changed: true},
			"pkg-c": {PackageName: "pkg-c", LatestVersion: "3.0.0", Changed: true},
		},
	}

	runner := NewRunner(wl, poller, fakeScanFunc(25.0), state.New(), nil)

	alerts, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}

	// All three should be in state.
	for _, name := range []string{"pkg-a", "pkg-b", "pkg-c"} {
		if _, ok := runner.State().Packages[name]; !ok {
			t.Errorf("expected %s in state", name)
		}
	}
}

func TestPollInterval(t *testing.T) {
	tests := []struct {
		risk string
		want time.Duration
	}{
		{"CRITICAL", 2 * time.Minute},
		{"HIGH", 2 * time.Minute},
		{"MEDIUM", 10 * time.Minute},
		{"LOW", 30 * time.Minute},
		{"", 30 * time.Minute},
	}
	for _, tt := range tests {
		if got := PollInterval(tt.risk); got != tt.want {
			t.Errorf("PollInterval(%q) = %v, want %v", tt.risk, got, tt.want)
		}
	}
}
