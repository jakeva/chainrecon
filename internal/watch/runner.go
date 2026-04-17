// Package watch implements the polling loop for monitoring npm packages.
package watch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jakeva/chainrecon/internal/alert"
	"github.com/jakeva/chainrecon/internal/analyzer"
	"github.com/jakeva/chainrecon/internal/collector/npm"
	"github.com/jakeva/chainrecon/internal/model"
	"github.com/jakeva/chainrecon/internal/scan"
	"github.com/jakeva/chainrecon/internal/state"
	"github.com/jakeva/chainrecon/internal/watchlist"
)

// ScanFunc runs a scan and returns the report.
type ScanFunc func(ctx context.Context, packageName, version string) (*model.Report, error)

// DiffFunc runs a diff between two versions and returns code findings.
type DiffFunc func(ctx context.Context, packageName, oldVersion, newVersion string) ([]model.CodeFinding, error)

// Option configures optional Runner behavior.
type Option func(*Runner)

// WithDiff enables release diffing when a new version is detected. The runner
// diffs against the previously scanned version and uses contextual scoring
// to adjust the target score.
func WithDiff(fn DiffFunc) Option {
	return func(r *Runner) { r.diffFn = fn }
}

// WithNotifier configures an alert notifier that fires when packages exceed
// their threshold.
func WithNotifier(n alert.Notifier) Option {
	return func(r *Runner) { r.notifier = n }
}

// Runner orchestrates the watch loop for a set of packages.
type Runner struct {
	watchlist *watchlist.Watchlist
	poller    npm.Poller
	scanFn    ScanFunc
	diffFn    DiffFunc
	notifier  alert.Notifier
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
	RiskLevel   string
	CodeRisk    float64
}

// NewRunner creates a new watch runner.
func NewRunner(wl *watchlist.Watchlist, p npm.Poller, scanFn ScanFunc, st *state.State, logf func(string, ...any), opts ...Option) *Runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r := &Runner{
		watchlist: wl,
		poller:    p,
		scanFn:    scanFn,
		state:     st,
		logf:      logf,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
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

				r.mu.Lock()
				ps, ok := r.state.Packages[entry.Name]
				r.mu.Unlock()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *Runner) pollAndScan(ctx context.Context, entry watchlist.Entry) error {
	r.mu.Lock()
	ps := r.state.Packages[entry.Name]
	r.mu.Unlock()

	r.logf("Polling %s ...\n", entry.Name)
	result, err := r.poller.Poll(ctx, entry.Name, ps.LastScannedVersion, ps.ETag)
	if err != nil {
		return err
	}

	// Skip scan if version has not changed and we have a previous scan.
	if !result.Changed && ps.LastScannedVersion != "" {
		r.logf("  %s: no change (v%s)\n", entry.Name, result.LatestVersion)
		// Update ETag even if no version change.
		r.mu.Lock()
		r.state.Update(entry.Name, ps.LastScannedVersion, ps.LastTargetScore, ps.LastRiskLevel, result.ETag)
		r.mu.Unlock()
		return nil
	}

	r.logf("  %s: scanning v%s ...\n", entry.Name, result.LatestVersion)
	report, err := r.scanFn(ctx, entry.Name, result.LatestVersion)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	targetScore := report.Scores.TargetScore
	var codeRisk float64
	var codeFindings []model.CodeFinding

	// Run diff analysis when a diff function is configured and we know the
	// previous version.
	if r.diffFn != nil && ps.LastScannedVersion != "" {
		r.logf("  %s: diffing %s -> %s ...\n", entry.Name, ps.LastScannedVersion, result.LatestVersion)
		findings, diffErr := r.diffFn(ctx, entry.Name, ps.LastScannedVersion, result.LatestVersion)
		if diffErr != nil {
			r.logf("  Warning: diff failed for %s: %v\n", entry.Name, diffErr)
		} else if len(findings) > 0 {
			combined := analyzer.CombineScores(report.Scores, findings)
			targetScore = combined.AdjustedTarget
			codeRisk = combined.CodeRisk
			codeFindings = findings
			r.logf("  %s: %d code finding(s), code_risk=%.1f, adjusted_score=%.1f\n",
				entry.Name, len(findings), codeRisk, targetScore)
		}
	}

	risk := analyzer.ClassifyRisk(targetScore)
	r.logf("  %s: score=%.1f (%s)\n", entry.Name, targetScore, risk)

	r.mu.Lock()
	r.state.Update(entry.Name, result.LatestVersion, targetScore, risk, result.ETag)
	r.mu.Unlock()

	threshold := r.watchlist.EffectiveThreshold(entry)
	if threshold > 0 && targetScore >= threshold {
		a := Alert{
			Package:     entry.Name,
			Version:     result.LatestVersion,
			TargetScore: targetScore,
			Threshold:   threshold,
			RiskLevel:   risk,
			CodeRisk:    codeRisk,
		}
		r.mu.Lock()
		r.alerts = append(r.alerts, a)
		r.mu.Unlock()
		r.logf("  ALERT: %s v%s score %.1f exceeds threshold %.1f\n",
			entry.Name, result.LatestVersion, targetScore, threshold)

		// Fire alert notification.
		if r.notifier != nil {
			event := alert.Event{
				Package:     a.Package,
				Version:     a.Version,
				TargetScore: a.TargetScore,
				Threshold:   a.Threshold,
				RiskLevel:   a.RiskLevel,
				Findings:    model.CodeFindingsToFindings(codeFindings),
			}
			if notifyErr := r.notifier.Notify(ctx, event); notifyErr != nil {
				r.logf("  Warning: alert notification failed: %v\n", notifyErr)
			}
		}
	}

	return nil
}

// PollInterval returns the polling interval for a given risk level.
func PollInterval(risk string) time.Duration {
	switch risk {
	case "CRITICAL", "HIGH":
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
