// Package watch implements the polling loop for monitoring npm packages.
package watch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chainrecon/chainrecon/internal/analyzer"
	"github.com/chainrecon/chainrecon/internal/collector/npm"
	"github.com/chainrecon/chainrecon/internal/model"
	"github.com/chainrecon/chainrecon/internal/scan"
	"github.com/chainrecon/chainrecon/internal/state"
	"github.com/chainrecon/chainrecon/internal/watchlist"
)

// ScanFunc runs a scan and returns the report.
type ScanFunc func(ctx context.Context, packageName, version string) (*model.Report, error)

// Runner orchestrates the watch loop for a set of packages.
type Runner struct {
	watchlist *watchlist.Watchlist
	poller    npm.Poller
	scanFn    ScanFunc
	state     *state.State
	logf      func(format string, args ...any)
	mu        sync.Mutex
	alerts    []Alert
}

// Alert records a package that exceeded its threshold.
type Alert struct {
	Package     string
	Version     string
	TargetScore float64
	Threshold   float64
}

// NewRunner creates a new watch runner.
func NewRunner(wl *watchlist.Watchlist, p npm.Poller, scanFn ScanFunc, st *state.State, logf func(string, ...any)) *Runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Runner{
		watchlist: wl,
		poller:    p,
		scanFn:    scanFn,
		state:     st,
		logf:      logf,
	}
}

// RunOnce performs a single pass over all packages: poll for changes, scan new
// versions, and return any alerts. This is the mode used by --once and CI.
func (r *Runner) RunOnce(ctx context.Context) ([]Alert, error) {
	for _, entry := range r.watchlist.Packages {
		if err := ctx.Err(); err != nil {
			return r.alerts, err
		}

		if err := r.pollAndScan(ctx, entry); err != nil {
			return r.alerts, fmt.Errorf("watch %s: %w", entry.Name, err)
		}
	}
	return r.alerts, nil
}

// RunContinuous polls packages at risk-based intervals until the context is
// cancelled. It returns accumulated alerts.
func (r *Runner) RunContinuous(ctx context.Context) ([]Alert, error) {
	// Initial pass to establish baselines.
	r.logf("Running initial scan pass ...\n")
	for _, entry := range r.watchlist.Packages {
		if err := ctx.Err(); err != nil {
			return r.alerts, nil
		}
		if err := r.pollAndScan(ctx, entry); err != nil {
			r.logf("Warning: initial scan of %s failed: %v\n", entry.Name, err)
		}
	}

	r.logf("Entering continuous watch mode ...\n")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return r.alerts, nil
		case <-ticker.C:
			for _, entry := range r.watchlist.Packages {
				if err := ctx.Err(); err != nil {
					return r.alerts, nil
				}

				ps, ok := r.state.Packages[entry.Name]
				if ok && time.Since(ps.LastScanTime) < PollInterval(ps.LastRiskLevel) {
					continue
				}

				if err := r.pollAndScan(ctx, entry); err != nil {
					r.logf("Warning: poll/scan of %s failed: %v\n", entry.Name, err)
				}
			}
		}
	}
}

// Alerts returns the current accumulated alerts.
func (r *Runner) Alerts() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.alerts
}

// State returns the current state for persistence.
func (r *Runner) State() *state.State {
	return r.state
}

func (r *Runner) pollAndScan(ctx context.Context, entry watchlist.Entry) error {
	ps := r.state.Packages[entry.Name]

	r.logf("Polling %s ...\n", entry.Name)
	result, err := r.poller.Poll(ctx, entry.Name, ps.LastScannedVersion, ps.ETag)
	if err != nil {
		return err
	}

	// Skip scan if version has not changed and we have a previous scan.
	if !result.Changed && ps.LastScannedVersion != "" {
		r.logf("  %s: no change (v%s)\n", entry.Name, result.LatestVersion)
		// Update ETag even if no version change.
		r.state.Update(entry.Name, ps.LastScannedVersion, ps.LastTargetScore, ps.LastRiskLevel, result.ETag)
		return nil
	}

	r.logf("  %s: scanning v%s ...\n", entry.Name, result.LatestVersion)
	report, err := r.scanFn(ctx, entry.Name, result.LatestVersion)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	risk := analyzer.ClassifyRisk(report.Scores.TargetScore)
	r.logf("  %s: score=%.1f (%s)\n", entry.Name, report.Scores.TargetScore, risk)

	r.state.Update(entry.Name, result.LatestVersion, report.Scores.TargetScore, risk, result.ETag)

	threshold := r.watchlist.EffectiveThreshold(entry)
	if threshold > 0 && report.Scores.TargetScore >= threshold {
		r.mu.Lock()
		r.alerts = append(r.alerts, Alert{
			Package:     entry.Name,
			Version:     result.LatestVersion,
			TargetScore: report.Scores.TargetScore,
			Threshold:   threshold,
		})
		r.mu.Unlock()
		r.logf("  ALERT: %s v%s score %.1f exceeds threshold %.1f\n",
			entry.Name, result.LatestVersion, report.Scores.TargetScore, threshold)
	}

	return nil
}

// PollInterval returns the polling interval for a given risk level.
func PollInterval(risk string) time.Duration {
	switch risk {
	case "CRITICAL":
		return 2 * time.Minute
	case "HIGH":
		return 2 * time.Minute
	case "MEDIUM":
		return 10 * time.Minute
	default:
		return 30 * time.Minute
	}
}

// DefaultScanFunc returns a ScanFunc that uses the real scan pipeline.
func DefaultScanFunc(opts scan.Options) ScanFunc {
	return func(ctx context.Context, packageName, version string) (*model.Report, error) {
		return scan.Run(ctx, packageName, version, opts)
	}
}
