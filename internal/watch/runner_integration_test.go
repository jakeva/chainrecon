package watch

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/model"
	"github.com/chainrecon/chainrecon/internal/state"
	"github.com/chainrecon/chainrecon/internal/watchlist"
)

// TestRunOnce_StatePersistsAcrossRuns verifies that when we save state after
// a RunOnce pass, a second pass with the same poller results skips scanning.
func TestRunOnce_StatePersistsAcrossRuns(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 80.0},
		Packages: []watchlist.Entry{
			{Name: "express"},
			{Name: "axios"},
		},
	}

	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"express": {PackageName: "express", LatestVersion: "4.18.2", Changed: true, ETag: `"e1"`},
			"axios":   {PackageName: "axios", LatestVersion: "1.7.0", Changed: true, ETag: `"a1"`},
		},
	}

	scanCount := 0
	scanFn := func(_ context.Context, pkg, version string) (*model.Report, error) {
		scanCount++
		return &model.Report{
			Package: pkg,
			Version: version,
			Scores:  model.Scores{TargetScore: 30.0},
		}, nil
	}

	// First run: both packages should be scanned.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	st := state.New()
	runner := NewRunner(wl, poller, scanFn, st, nil)

	_, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	if scanCount != 2 {
		t.Fatalf("first pass: expected 2 scans, got %d", scanCount)
	}

	// Save state.
	if err := state.Save(statePath, runner.State()); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	// Second run: load persisted state, same poller returns Changed=false.
	poller.results = map[string]npm.PollResult{
		"express": {PackageName: "express", LatestVersion: "4.18.2", Changed: false, ETag: `"e1"`},
		"axios":   {PackageName: "axios", LatestVersion: "1.7.0", Changed: false, ETag: `"a1"`},
	}

	st2, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}

	scanCount = 0
	runner2 := NewRunner(wl, poller, scanFn, st2, nil)

	_, err = runner2.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if scanCount != 0 {
		t.Errorf("second pass: expected 0 scans (unchanged), got %d", scanCount)
	}
}

// TestRunOnce_NewVersionTriggersRescan verifies that when a package gets a new
// version between runs, it gets rescanned even though we have prior state.
func TestRunOnce_NewVersionTriggersRescan(t *testing.T) {
	wl := &watchlist.Watchlist{
		Packages: []watchlist.Entry{
			{Name: "express"},
		},
	}

	// Pre-populate state from a previous run.
	st := state.New()
	st.Update("express", "4.18.2", 30.0, "LOW", `"e1"`)

	// Poller reports a new version.
	poller := &fakePoller{
		results: map[string]npm.PollResult{
			"express": {PackageName: "express", LatestVersion: "4.19.0", Changed: true, ETag: `"e2"`},
		},
	}

	scannedVersion := ""
	scanFn := func(_ context.Context, _, version string) (*model.Report, error) {
		scannedVersion = version
		return &model.Report{
			Scores: model.Scores{TargetScore: 35.0},
		}, nil
	}

	runner := NewRunner(wl, poller, scanFn, st, nil)
	_, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if scannedVersion != "4.19.0" {
		t.Errorf("expected scan of 4.19.0, got %q", scannedVersion)
	}

	// State should reflect the new version.
	ps := runner.State().Packages["express"]
	if ps.LastScannedVersion != "4.19.0" {
		t.Errorf("state version = %q, want 4.19.0", ps.LastScannedVersion)
	}
	if ps.ETag != `"e2"` {
		t.Errorf("state etag = %q, want %q", ps.ETag, `"e2"`)
	}
}

// TestConcurrentStateAccess verifies that calling State() and Alerts() from
// another goroutine while RunOnce is executing doesn't race.
func TestConcurrentStateAccess(t *testing.T) {
	wl := &watchlist.Watchlist{
		Defaults: watchlist.Defaults{Threshold: 50.0},
		Packages: []watchlist.Entry{
			{Name: "pkg-1"},
			{Name: "pkg-2"},
			{Name: "pkg-3"},
			{Name: "pkg-4"},
			{Name: "pkg-5"},
		},
	}

	results := make(map[string]npm.PollResult, 5)
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("pkg-%d", i)
		results[name] = npm.PollResult{
			PackageName:   name,
			LatestVersion: "1.0.0",
			Changed:       true,
		}
	}

	poller := &fakePoller{results: results}
	runner := NewRunner(wl, poller, fakeScanFunc(60.0), state.New(), nil)

	var wg sync.WaitGroup

	// Reader goroutine: continuously access State() and Alerts().
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_ = runner.State()
			_ = runner.Alerts()
		}
	}()

	// Run the scan.
	alerts, err := runner.RunOnce(context.Background())
	cancel()
	wg.Wait()

	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}
}
