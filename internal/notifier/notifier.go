// Package notifier dispatches findings to webhook and email sinks, gated by severity.
package notifier

import (
	"context"
	"log/slog"

	"openticollect/internal/models"
)

// Sink is one delivery channel.
type Sink interface {
	Name() string
	MinSeverity() string
	Send(ctx context.Context, f models.Finding) error
}

type Notifier struct {
	sinks []Sink
	log   *slog.Logger
}

// New builds a Notifier. A nil logger is replaced with the slog default.
func New(log *slog.Logger, sinks ...Sink) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{sinks: sinks, log: log}
}

// Dispatch sends each finding to every sink whose MinSeverity it meets.
// Sink errors are logged, never returned — one bad sink must not block others.
func (n *Notifier) Dispatch(ctx context.Context, findings []models.Finding) {
	for _, f := range findings {
		for _, sink := range n.sinks {
			if models.SeverityRank(f.Severity) < models.SeverityRank(sink.MinSeverity()) {
				continue
			}
			if err := sink.Send(ctx, f); err != nil {
				n.log.Error("notifier: send failed",
					"sink", sink.Name(), "finding", f.ID, "err", err)
			}
		}
	}
}
