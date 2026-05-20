package notifier

import (
	"context"
	"sync"
	"testing"

	"openticollect/internal/models"
)

// recordingSink captures everything sent to it.
type recordingSink struct {
	mu   sync.Mutex
	min  string
	sent []models.Finding
}

func (r *recordingSink) Name() string        { return "recording" }
func (r *recordingSink) MinSeverity() string { return r.min }
func (r *recordingSink) Send(_ context.Context, f models.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, f)
	return nil
}

func TestDispatchSeverityGating(t *testing.T) {
	sink := &recordingSink{min: "warn"}
	n := New(nil, sink)

	n.Dispatch(context.Background(), []models.Finding{
		{ID: 1, Severity: "info"},
		{ID: 2, Severity: "warn"},
		{ID: 3, Severity: "critical"},
	})

	if len(sink.sent) != 2 {
		t.Fatalf("expected 2 findings to pass the warn gate, got %d", len(sink.sent))
	}
	if sink.sent[0].ID != 2 || sink.sent[1].ID != 3 {
		t.Fatalf("wrong findings passed: %#v", sink.sent)
	}
}

func TestDispatchNoSinksIsNoop(t *testing.T) {
	n := New(nil)
	n.Dispatch(context.Background(), []models.Finding{{ID: 1, Severity: "critical"}})
	// no panic == pass
}
