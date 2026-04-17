// Package alert provides notification backends for watch alerts.
package alert

import (
	"context"
	"fmt"

	"github.com/jakeva/chainrecon/internal/model"
)

// Event holds the details of an alert that should be sent to notification backends.
type Event struct {
	Package     string          `json:"package"`
	Version     string          `json:"version"`
	TargetScore float64         `json:"target_score"`
	Threshold   float64         `json:"threshold"`
	RiskLevel   string          `json:"risk_level"`
	Findings    []model.Finding `json:"findings,omitempty"`
}

// Notifier sends alerts to an external system.
type Notifier interface {
	// Notify sends a single alert event. Implementations should be safe for
	// concurrent use.
	Notify(ctx context.Context, event Event) error

	// Name returns a short identifier for this notifier (e.g., "webhook", "slack").
	Name() string
}

// Multi fans out alerts to multiple notifiers. If any notifier fails, the error
// is collected but delivery continues to the remaining notifiers.
type Multi struct {
	notifiers []Notifier
}

// NewMulti creates a notifier that sends to all provided backends.
func NewMulti(notifiers ...Notifier) *Multi {
	return &Multi{notifiers: notifiers}
}

// Notify sends the event to all configured notifiers. Returns a combined error
// if any fail.
func (m *Multi) Notify(ctx context.Context, event Event) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, event); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	msg := "multiple notification failures:"
	for _, e := range errs {
		msg += "\n  " + e.Error()
	}
	return fmt.Errorf("%s", msg)
}

// Name implements Notifier.
func (m *Multi) Name() string { return "multi" }
